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

use Exception;
use FSG\Oidc\Domain\Model\Dto\ExtensionConfiguration;
use FSG\Oidc\Error\InvalidStateException;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Provider\GenericProvider;
use League\OAuth2\Client\Token\AccessToken;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Database\Query\Restriction\DefaultRestrictionContainer;
use TYPO3\CMS\Core\Database\Query\Restriction\DeletedRestriction;
use TYPO3\CMS\Core\Database\Query\Restriction\EndTimeRestriction;
use TYPO3\CMS\Core\Database\Query\Restriction\HiddenRestriction;
use TYPO3\CMS\Core\Database\Query\Restriction\QueryRestrictionContainerInterface;
use TYPO3\CMS\Core\Database\Query\Restriction\StartTimeRestriction;
use TYPO3\CMS\Core\Session\Backend\Exception\SessionNotCreatedException;
use TYPO3\CMS\Core\Session\Backend\Exception\SessionNotFoundException;
use TYPO3\CMS\Core\Session\Backend\Exception\SessionNotUpdatedException;
use TYPO3\CMS\Core\Session\Backend\SessionBackendInterface;
use TYPO3\CMS\Core\Session\SessionManager;
use TYPO3\CMS\Core\SysLog\Action\Login as SystemLogLoginAction;
use TYPO3\CMS\Core\SysLog\Error as SystemLogErrorClassification;
use TYPO3\CMS\Core\SysLog\Type as SystemLogType;
use TYPO3\CMS\Core\Utility\GeneralUtility;
use TYPO3\CMS\Core\Utility\HttpUtility;

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
     * @var GenericProvider
     */
    protected GenericProvider $oauthClient;

    /**
     * @var SessionBackendInterface
     */
    private SessionBackendInterface $session;

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
     * Finds a user.
     *
     * @return array<string, mixed>|null
     * @throws Exception
     */
    public function getUser(): ?array
    {
        $this->manageAuthentication();
        return $this->manageCallback();
    }

    /**
     * Manage the authentication process
     *
     * @throws SessionNotCreatedException
     * @throws SessionNotUpdatedException
     */
    protected function manageAuthentication(): void
    {
        if (GeneralUtility::_GP('oidc-signin')) {
            $this->authenticateUser();
        }
    }

    /**
     * Manage the callback process
     *
     * @return array<string, mixed>|null
     */
    protected function manageCallback(): ?array
    {
        if ($providedState = GeneralUtility::_GP('state')) {
            try {
                $expectedState = $this->session->get('t3oidcOAuthState')['ses_data'];
                $this->session->remove('t3oidcOAuthState');

                if ($expectedState != $providedState) {
                    throw new InvalidStateException(
                        'The provided auth state did not match the expected value',
                        1613752400
                    );
                }

                if ($code = GeneralUtility::_GP('code')) {
                    /**
                     * @var AccessToken $accessToken
                     */
                    $accessToken   = $this->getOAuthClient()->getAccessToken('authorization_code', ['code' => $code]);
                    $resourceOwner = $this->getOAuthClient()->getResourceOwner($accessToken)->toArray();

                    $queryBuilder      = GeneralUtility::makeInstance(ConnectionPool::class)
                                                       ->getQueryBuilderForTable($this->db_user['table']);
                    $expressionBuilder = $queryBuilder->expr();

                    $dbUser = array_merge(
                        $this->db_user,
                        [
                            'username_column' => 'oidc_identifier',
                            'enable_clause'   => $this->userConstraints()
                                                      ->buildExpression(
                                                          [
                                                              $this->db_user['table'] => $this->db_user['table'],
                                                          ],
                                                          $expressionBuilder
                                                      ),
                        ]
                    );

                    if (!($user = $this->fetchUserRecord($resourceOwner['sub'], '', $dbUser))
                        && !$this->extensionConfiguration->isBackendUserMustExistLocally()) {
                        // create local user
                    } elseif ($user['disable'] == 1 || $user['deleted'] == 1) {
                        // In case user was disabled or deleted, reset it
                    }
                    return $user;
                }
            } catch (SessionNotFoundException | InvalidStateException | IdentityProviderException $e) {
                $this->logger->error($e->getMessage());
                HttpUtility::redirect($this->getCallbackUrl($e->getCode()));
            }
        }
        return null;
    }

    /**
     * Initialize local session and redirect to the authentication service.
     *
     * @throws SessionNotCreatedException
     * @throws SessionNotUpdatedException
     */
    protected function authenticateUser(): void
    {
        $authorizationUrl = $this->getOAuthClient()->getAuthorizationUrl();

        try {
            $this->session->get('t3oidcOAuthState');
            $this->session->update('t3oidcOAuthState', ['ses_data' => $this->getOAuthClient()->getState()]);
        } catch (SessionNotFoundException $e) {
            $this->session->set('t3oidcOAuthState', ['ses_data' => $this->getOAuthClient()->getState()]);
        }

        HttpUtility::redirect($authorizationUrl);
    }

    /**
     * @return GenericProvider
     */
    protected function getOAuthClient(): GenericProvider
    {
        if (!isset($this->oauthClient)) {
            $this->oauthClient = new GenericProvider(
                [
                    'clientId'                => $this->extensionConfiguration->getClientId(),
                    'clientSecret'            => $this->extensionConfiguration->getClientSecret(),
                    'redirectUri'             => $this->getCallbackUrl(),
                    'urlAuthorize'            => $this->extensionConfiguration->getEndpointAuthorize(),
                    'urlAccessToken'          => $this->extensionConfiguration->getEndpointToken(),
                    'urlResourceOwnerDetails' => $this->extensionConfiguration->getEndpointUserInfo(),
                    'scopes'                  => GeneralUtility::trimExplode(
                        ',',
                        $this->extensionConfiguration->getClientScopes(),
                        true
                    ),
                ]
            );
        }

        return $this->oauthClient;
    }

    /**
     * @param int|null $error
     *
     * @return string
     */
    protected function getCallbackUrl(?int $error = null): string
    {
        $callback = GeneralUtility::getIndpEnv('TYPO3_REQUEST_HOST');
        if ($this->mode === 'getUserBE') {
            $callback .= '/typo3/?' . (!is_null($error) ? 'error=' . $error : 'login_status=login');
        }
        return $callback;
    }

    /**
     * This returns the restrictions needed to select the user respecting
     * enable columns and flags like deleted, hidden, starttime, endtime
     * and rootLevel
     *
     * @return QueryRestrictionContainerInterface
     */
    protected function userConstraints(): QueryRestrictionContainerInterface
    {
        $restrictionContainer = GeneralUtility::makeInstance(DefaultRestrictionContainer::class);

        $restrictionContainer->removeByType(StartTimeRestriction::class);
        $restrictionContainer->removeByType(EndTimeRestriction::class);

        if ($this->mode == 'BE') {
            if ($this->extensionConfiguration->isReEnableBackendUsers()) {
                $restrictionContainer->removeByType(HiddenRestriction::class);
            }

            if ($this->extensionConfiguration->isUnDeleteBackendUsers()) {
                $restrictionContainer->removeByType(DeletedRestriction::class);
            }
        }

        return $restrictionContainer;
    }

    /**
     * @param array<string, mixed> $user
     *
     * @return int
     */
    public function authUser(array $user): int
    {
        if (!isset($user['oidc_identifier']) || (string)$user['oidc_identifier'] === '') {
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
            $user['username']
        );
        return 200;
    }
}
