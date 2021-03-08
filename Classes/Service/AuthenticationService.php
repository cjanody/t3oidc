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

use FSG\Oidc\Domain\Model\Dto\ExtensionConfiguration;
use TYPO3\CMS\Core\Authentication\AbstractUserAuthentication;
use TYPO3\CMS\Core\Authentication\LoginType;
use TYPO3\CMS\Core\Session\Backend\Exception\SessionNotFoundException;
use TYPO3\CMS\Core\Session\Backend\SessionBackendInterface;
use TYPO3\CMS\Core\Session\SessionManager;
use TYPO3\CMS\Core\SysLog\Action\Login as SystemLogLoginAction;
use TYPO3\CMS\Core\SysLog\Error as SystemLogErrorClassification;
use TYPO3\CMS\Core\SysLog\Type as SystemLogType;
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
        if ($this->initializeUserInfo()) {
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

    protected function handleLogin(): void
    {
        if ($this->login['responsible'] === true) {
            switch ($this->mode) {
                case 'getUserFE':
                case 'getUserBE':
                    $this->logger->debug(sprintf('Process auth mode "%s".', $this->mode));
                    // $this->insertOrUpdateUser();
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
     * @param array<string, mixed> $user
     *
     * @return int
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
            // Password ok, but configured domain lock not met
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
}
