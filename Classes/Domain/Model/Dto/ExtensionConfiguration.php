<?php

declare(strict_types=1);

namespace FSG\Oidc\Domain\Model\Dto;

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

use TYPO3\CMS\Core\SingletonInterface;
use TYPO3\CMS\Core\Utility\GeneralUtility;

/**
 * Class ExtensionConfiguration
 */
class ExtensionConfiguration implements SingletonInterface
{
    /**
     * @var string
     */
    protected string $clientId = '';

    /**
     * @var string
     */
    protected string $clientSecret = '';

    /**
     * @var string
     */
    protected string $clientScopes = '';

    /**
     * @var string
     */
    protected string $endpointAuthorize = '';

    /**
     * @var string
     */
    protected string $endpointToken = '';

    /**
     * @var string
     */
    protected string $endpointUserInfo = '';

    /**
     * @var string
     */
    protected string $endpointLogout = '';

    /**
     * @var bool
     */
    protected bool $enableBackendAuthentication = false;

    /**
     * @var bool
     */
    protected bool $backendUserMustExistLocally = false;

    /**
     * @var bool
     */
    protected bool $reEnableBackendUsers = false;

    /**
     * @var bool
     */
    protected bool $unDeleteBackendUsers = false;

    /**
     * @var string
     */
    protected string $tokenUserIdentifier = '';

    /**
     * ExtensionConfiguration constructor.
     */
    public function __construct()
    {
        $settings = GeneralUtility::makeInstance(\TYPO3\CMS\Core\Configuration\ExtensionConfiguration::class)
                                  ->get('t3oidc');

        foreach ($settings as $key => $value) {
            if (property_exists($this, $key)) {
                settype($value, gettype($this->$key));
                $this->$key = $value;
            }
        }
    }

    /**
     * @return string
     */
    public function getClientId(): string
    {
        return $this->clientId;
    }

    /**
     * @return string
     */
    public function getClientSecret(): string
    {
        return $this->clientSecret;
    }

    /**
     * @return string
     */
    public function getClientScopes(): string
    {
        return $this->clientScopes;
    }

    /**
     * @return string
     */
    public function getEndpointAuthorize(): string
    {
        return $this->endpointAuthorize;
    }

    /**
     * @return string
     */
    public function getEndpointToken(): string
    {
        return $this->endpointToken;
    }

    /**
     * @return string
     */
    public function getEndpointUserInfo(): string
    {
        return $this->endpointUserInfo;
    }

    /**
     * @return string
     */
    public function getEndpointLogout(): string
    {
        return $this->endpointLogout;
    }

    /**
     * @return bool
     */
    public function isEnableBackendAuthentication(): bool
    {
        return $this->enableBackendAuthentication;
    }

    /**
     * @return bool
     */
    public function isBackendUserMustExistLocally(): bool
    {
        return $this->backendUserMustExistLocally;
    }

    /**
     * @return bool
     */
    public function isReEnableBackendUsers(): bool
    {
        return $this->reEnableBackendUsers;
    }

    /**
     * @return bool
     */
    public function isUnDeleteBackendUsers(): bool
    {
        return $this->unDeleteBackendUsers;
    }

    /**
     * @return string
     */
    public function getTokenUserIdentifier(): string
    {
        return $this->tokenUserIdentifier;
    }
}
