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
use TYPO3\CMS\Core\Session\Backend\Exception\SessionNotCreatedException;
use TYPO3\CMS\Core\Session\Backend\Exception\SessionNotFoundException;
use TYPO3\CMS\Core\Session\Backend\Exception\SessionNotUpdatedException;
use TYPO3\CMS\Core\Session\Backend\SessionBackendInterface;
use TYPO3\CMS\Core\Session\SessionManager;
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
     * @throws Exception
     */
    public function getUser(): void
    {
        if (GeneralUtility::_GP('oidc-signin')) {
            $this->authenticateUser();
        } elseif ($providedState = GeneralUtility::_GP('state')) {
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
                    $accessToken = $this->getOAuthClient()->getAccessToken('authorization_code', ['code' => $code]);
                }
            } catch (SessionNotFoundException | InvalidStateException | IdentityProviderException $e) {
                $this->logger->error($e->getMessage());
                HttpUtility::redirect($this->getCallbackUrl($e->getCode()));
            }
        }
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
}
