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
use FSG\Oidc\Error\ConfigurationException;
use FSG\Oidc\Error\HTTPSConnectionException;
use TYPO3\CMS\Core\Utility\GeneralUtility;
use UnexpectedValueException;

/**
 * Class StatusService
 *
 * This class is used to validate that the minimum configurations are set and if the service is enabled for the mode
 * provided.
 */
class StatusService
{
    /**
     * @param string $mode
     *
     * @return bool
     * @throws UnexpectedValueException|HTTPSConnectionException|ConfigurationException
     */
    public static function isEnabled(string $mode): bool
    {
        if (!GeneralUtility::inList('BE', $mode)) {
            throw new UnexpectedValueException(sprintf('Mode "%s" is not supported', $mode), 1613676690);
        }

        if (!$GLOBALS['TYPO3_REQUEST']->getAttribute('normalizedParams')->isHttps()) {
            throw new HTTPSConnectionException('HTTPS is required', 1613676691);
        }

        /**
         * @var ExtensionConfiguration $extensionConfiguration
         */
        $extensionConfiguration = GeneralUtility::makeInstance(ExtensionConfiguration::class);

        if (!$extensionConfiguration->getClientId()) {
            throw new ConfigurationException('No client ID is set', 1613676692);
        }

        if (!$extensionConfiguration->getClientSecret()) {
            throw new ConfigurationException('No client secret is set', 1613676693);
        }

        if (!$extensionConfiguration->getClientScopes()) {
            throw new ConfigurationException('No client scope is set', 1613676694);
        }

        if (!$extensionConfiguration->getEndpointAuthorize()) {
            throw new ConfigurationException('No authorize endpoint is set', 1613676695);
        }

        if (!$extensionConfiguration->getEndpointToken()) {
            throw new ConfigurationException('No token endpoint is set', 1613676696);
        }

        if (!$extensionConfiguration->getEndpointUserInfo()) {
            throw new ConfigurationException('No userinfo endpoint is set', 1613676697);
        }

        if (!$extensionConfiguration->getTokenUserIdentifier()) {
            throw new ConfigurationException('No token user identifier is set', 1613676698);
        }

        if ($mode === 'BE') {
            return $extensionConfiguration->isEnableBackendAuthentication();
        }

        return false;
    }
}
