<?php

declare(strict_types=1);

namespace FSG\Oidc\Service;

/*
 * This file is part of the TYPO3 CMS project.
 *
 * It is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License, either version 2
 * of the License, or any later version.
 *
 * For the full copyright and license information, please read the
 * LICENSE.txt file that was distributed with this source code.
 *
 * The TYPO3 project - inspiring people to share!
 */

use DateTime;
use Doctrine\DBAL\Driver\Exception;
use Doctrine\DBAL\Driver\Result;
use FSG\Oidc\Domain\Model\Dto\ExtensionConfiguration;
use FSG\Oidc\LoginProvider\OpenIDConnectSignInProvider;
use PDO;
use TYPO3\CMS\Core\Authentication\AbstractUserAuthentication;
use TYPO3\CMS\Core\Authentication\LoginType;
use TYPO3\CMS\Core\Crypto\PasswordHashing\InvalidPasswordHashException;
use TYPO3\CMS\Core\Crypto\PasswordHashing\PasswordHashFactory;
use TYPO3\CMS\Core\Crypto\Random;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Database\Query\QueryBuilder;
use TYPO3\CMS\Core\Session\Backend\Exception\SessionNotFoundException;
use TYPO3\CMS\Core\Session\Backend\SessionBackendInterface;
use TYPO3\CMS\Core\Session\SessionManager;
use TYPO3\CMS\Core\SysLog\Action\Login as SystemLogLoginAction;
use TYPO3\CMS\Core\SysLog\Error as SystemLogErrorClassification;
use TYPO3\CMS\Core\SysLog\Type as SystemLogType;
use TYPO3\CMS\Core\Utility\ArrayUtility;
use TYPO3\CMS\Core\Utility\GeneralUtility;

/**
 * OpenID Connect authentication service.
 */
class AuthenticationService extends \TYPO3\CMS\Core\Authentication\AuthenticationService
{
    /**
     * @var ExtensionConfiguration
     */
    protected ExtensionConfiguration $extensionConfiguration;

    /**
     * @var SessionBackendInterface
     */
    private SessionBackendInterface $session;

    /**
     * @var array<string, string>
     */
    private array $userInfo = [];

    /**
     * @var QueryBuilder
     */
    private QueryBuilder $queryBuilder;

    /**
     * AuthenticationService constructor.
     */
    public function __construct()
    {
        $this->extensionConfiguration = GeneralUtility::makeInstance(ExtensionConfiguration::class);
        $this->session                = GeneralUtility::makeInstance(SessionManager::class)
                                                      ->getSessionBackend(TYPO3_MODE);
    }

    /**
     * @param string                     $mode
     * @param array<string, string>      $loginData
     * @param array<string, string>      $authInfo
     * @param AbstractUserAuthentication $pObj
     */
    public function initAuth($mode, $loginData, $authInfo, $pObj): void
    {
        parent::initAuth($mode, $loginData, $authInfo, $pObj);

        $this->login['responsible'] = false;
        if (GeneralUtility::_GP('loginProvider') == OpenIDConnectSignInProvider::LOGIN_PROVIDER
            && $this->initializeUserInfo()) {
            $this->login['status']      = 'login';
            $this->login['responsible'] = true;
            $this->handleLogin();
        }
    }

    /**
     * Initializes UserInfo if session exists
     */
    protected function initializeUserInfo(): bool
    {
        try {
            if ($this->userInfo = unserialize($this->session->get('t3oidcOAuthUser')['ses_data'])) {
                return true;
            }
        } catch (SessionNotFoundException $e) {
            $this->logger->error(sprintf('Error %s: %s', $e->getCode(), $e->getMessage()));
        }

        return false;
    }

    /**
     * @throws Exception|InvalidPasswordHashException
     */
    protected function handleLogin(): void
    {
        if ($this->login['responsible'] === true) {
            switch ($this->mode) {
                case 'getUserFE':
                case 'getUserBE':
                    $this->logger->debug(sprintf('Process auth mode "%s".', $this->mode));
                    $this->insertOrUpdateUser();
                    break;
                case 'authUserFE':
                case 'authUserBE':
                    $this->logger->debug(sprintf('Skip auth mode "%s".', $this->mode));
                    break;
                default:
                    $this->logger->notice(sprintf('Undefined mode "%s". Skip.', $this->mode));
            }
        }
    }

    /**
     * Insert or update logged in user
     *
     * @return array<string, string> $user
     * @throws Exception|InvalidPasswordHashException
     */
    protected function insertOrUpdateUser(): array
    {
        $this->queryBuilder = GeneralUtility::makeInstance(ConnectionPool::class)
                                            ->getQueryBuilderForTable($this->db_user['table']);

        $user = $this->fetchUserIfItExists();

        // Insert a new user into database
        if (empty($user) && !$this->extensionConfiguration->isBackendUserMustExistLocally()) {
            $this->logger->notice(
                'Insert new user.',
                [
                    $this->db_user['username_column'] => $this->userInfo[$this->extensionConfiguration->getTokenUserIdentifier()],
                ]
            );
            $user = $this->insertUser();
        } elseif (!empty($user)) {
            if ($this->authInfo['loginType'] == 'BE'
                && ($user['deleted'] == 0
                    || $this->extensionConfiguration->isUnDeleteBackendUsers())
                && ($user['disable'] == 0 || $this->extensionConfiguration->isReEnableBackendUsers())) {
                if (!$this->updateUser($user)) {
                    $this->logger->error(
                        'User found but it was not updated!',
                        [
                            $this->db_user['userid_column']   => $user[$this->db_user['userid_column']],
                            $this->db_user['username_column'] => $user[$this->db_user['username_column']],
                        ]
                    );
                }
            } else {
                $user = [];
            }
        }

        return $user;
    }

    /**
     * This returns the logged in user record if it exists locally
     *
     * @return array<string, mixed>
     * @throws Exception
     */
    protected function fetchUserIfItExists(): array
    {
        $query = $this->queryBuilder;
        $query->getRestrictions()->removeAll();
        $constraint = $query->expr()->eq(
            'oidc_identifier',
            $query->createNamedParameter(
                $this->userInfo[$this->extensionConfiguration->getTokenUserIdentifier()],
                PDO::PARAM_STR
            )
        );

        /** @var Result $result */
        $result = $query->select('*')
                        ->from($this->db_user['table'])
                        ->where($constraint)
                        ->execute();

        return $result->fetchAssociative() ?: [];
    }

    /**
     * This update the logged in user record
     *
     * @param array<string, mixed> $user
     *
     * @return bool
     */
    protected function updateUser(array &$user): bool
    {
        $endtime = new DateTime('today +3 month');
        $updated = $this->queryBuilder->update($this->db_user['table'])
                                      ->set('realName', $this->userInfo['name'])
                                      ->set('email', $this->userInfo['email'])
                                      ->set('deleted', '0', true, PDO::PARAM_INT)
                                      ->set('disable', '0', true, PDO::PARAM_INT)
                                      ->set('starttime', '0', true, PDO::PARAM_INT)
                                      ->set('endtime', (string)$endtime->getTimestamp(), true, PDO::PARAM_INT)
                                      ->where(
                                          $this->queryBuilder->expr()->eq(
                                              'uid',
                                              $this->queryBuilder->createNamedParameter($user['uid'], PDO::PARAM_INT)
                                          )
                                      )
                                      ->execute() ? true : false;

        if ($updated) {
            $user['realName']  = $this->userInfo['name'];
            $user['email']     = $this->userInfo['email'];
            $user['starttime'] = 0;
            $user['endtime']   = $endtime->getTimestamp();
            $user['deleted']   = 0;
            $user['disable']   = 0;
        }

        return $updated;
    }

    /**
     * Find a user
     *
     * @return array<string,string>|null
     */
    public function getUser(): ?array
    {
        if ($this->login['status'] !== LoginType::LOGIN
            || $this->login['responsible'] === false
            || !isset($this->userInfo[$this->extensionConfiguration->getTokenUserIdentifier()])) {
            return null;
        }

        $dbUser = array_merge($this->db_user, ['username_column' => 'oidc_identifier']);
        $user   = $this->fetchUserRecord(
            $this->userInfo[$this->extensionConfiguration->getTokenUserIdentifier()],
            '',
            $dbUser
        ) ?: null;

        if (!is_array($user)) {
            // Failed login attempt (no username found)
            $this->writelog(
                SystemLogType::LOGIN,
                SystemLogLoginAction::ATTEMPT,
                SystemLogErrorClassification::SECURITY_NOTICE,
                2,
                'Login-attempt from ###IP###, username \'%s\' not found!!',
                [$this->login['uname']]
            );
            $this->logger->info(
                'Login-attempt from username \'' . $this->login['uname'] . '\' not found!',
                [
                    'REMOTE_ADDR' => $this->authInfo['REMOTE_ADDR'],
                ]
            );
        } else {
            $this->logger->debug(
                'User found',
                [
                    $this->db_user['userid_column']   => $user[$this->db_user['userid_column']],
                    $this->db_user['username_column'] => $user[$this->db_user['username_column']],
                ]
            );
        }

        return $user;
    }

    /**
     * Authenticate a user: Check user identifier if the service is responsible of the authentication and check domain
     * lock if configured.
     *
     * Returns one of the following status codes:
     *  >= 200: User authenticated successfully. No more checking is needed by other auth services.
     *  >= 100: User not authenticated; this service is not responsible. Other auth services will be asked.
     *  > 0:    User authenticated successfully. Other auth services will still be asked.
     *  <= 0:   Authentication failed, no more checking needed by other auth services.
     *
     * @param array<string, mixed> $user User data
     *
     * @return int Authentication status code, one of 0, 100, 200
     */
    public function authUser(array $user): int
    {
        if ($this->login['responsible'] === false) {
            // Service is not responsible. Check other services.
            return 100;
        }
        if (empty($user['oidc_identifier'])
            || (string)$user['oidc_identifier']
               !== $this->userInfo[$this->extensionConfiguration->getTokenUserIdentifier()]) {
            // Verification failed as identifier does not match. Maybe other services can handle this login.
            return 100;
        }

        $queriedDomain   = $this->authInfo['HTTP_HOST'];
        $isDomainLockMet = false;

        if (empty($user['lockToDomain'])) {
            // No domain restriction set for user in db. This is ok.
            $isDomainLockMet = true;
        } elseif (!strcasecmp($user['lockToDomain'], $queriedDomain)) {
            // Domain restriction set and it matches given host. Ok.
            $isDomainLockMet = true;
        }

        if (!$isDomainLockMet) {
            // Configured domain lock not met
            $errorMessage = 'Login-attempt from ###IP###, username \'%s\', locked domain \'%s\' did not match \'%s\'!';
            $this->writeLogMessage(
                $errorMessage,
                $user[$this->db_user['username_column']],
                $user['lockToDomain'],
                $queriedDomain
            );
            $this->writelog(
                SystemLogType::LOGIN,
                SystemLogLoginAction::ATTEMPT,
                SystemLogErrorClassification::SECURITY_NOTICE,
                1,
                $errorMessage,
                [$user[$this->db_user['username_column']], $user['lockToDomain'], $queriedDomain]
            );
            $this->logger->info(sprintf(
                                    $errorMessage,
                                    $user[$this->db_user['username_column']],
                                    $user['lockToDomain'],
                                    $queriedDomain
                                ));
            // Responsible, authentication ok, but domain lock not ok, do NOT check other services
            return 0;
        }

        // Responsible, authentication ok, domain lock ok. Log successful login and return 'auth ok, do NOT check other services'
        $this->writeLogMessage(
            $this->pObj->loginType . ' Authentication successful for username \'%s\'',
            $user[$this->db_user['username_column']]
        );
        return 200;
    }

    /**
     * @throws InvalidPasswordHashException
     */
    public function insertUser(): array
    {
        switch ($this->db_user['table']) {
            case 'fe_users':
                // $this->insertFeUser();
                break;
            case 'be_users':
                $user = $this->insertBeUser();
                break;
            default:
                $this->logger->error(sprintf('"%s" is not a valid table name.', $this->db_user['table']));
        }
        return $user ?? [];
    }

    /**
     * Inserts a new backend user
     *
     * @throws InvalidPasswordHashException
     */
    public function insertBeUser(): array
    {
        $defaults = $this->getTcaDefaults();
        $endtime  = new DateTime('today +3 month');

        $preset = [
            'pid'             => 0,
            'tstamp'          => time(),
            'crdate'          => time(),
            'disable'         => 0,
            'endtime'         => $endtime->getTimestamp(),
            'username'        => $this->userInfo[$this->extensionConfiguration->getTokenUserIdentifier()],
            'password'        => $this->getPassword(),
            'email'           => $this->userInfo['email'] ?? '',
            'oidc_identifier' => $this->userInfo[$this->extensionConfiguration->getTokenUserIdentifier()],
        ];

        $values = array_merge($defaults, $preset);

        $query  = $this->queryBuilder;
        $result = $query->insert($this->db_user['table'])->values($values)->execute();

        return $this->fetchUserRecord($preset['oidc_identifier']);
    }

    protected function getTcaDefaults(): array
    {
        $defaults = [];
        $columns  = $GLOBALS['TCA'][$this->db_user['table']]['columns'] ?? [];

        foreach ($columns as $fieldName => $field) {
            if (isset($field['config']['default'])) {
                $defaults[$fieldName] = $field['config']['default'];
            }
        }

        return $defaults;
    }

    /**
     * @throws InvalidPasswordHashException
     */
    protected function getPassword(): string
    {
        $saltFactory = GeneralUtility::makeInstance(PasswordHashFactory::class)->getDefaultHashInstance(TYPO3_MODE);
        $password    = GeneralUtility::makeInstance(Random::class)->generateRandomHexString(50);

        return $saltFactory->getHashedPassword($password);
    }
}
