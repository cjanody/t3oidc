<?php

defined('TYPO3_MODE') || die();

(static function (string $extKey) {
    /**
     * Configuration of authentication service
     *
     * @var \FSG\Oidc\Domain\Model\Dto\ExtensionConfiguration $settings
     */
    $settings = \TYPO3\CMS\Core\Utility\GeneralUtility::makeInstance(
        FSG\Oidc\Domain\Model\Dto\ExtensionConfiguration::class
    );

    if ((bool)$settings->isEnableBackendAuthentication()) {
        $GLOBALS['TYPO3_CONF_VARS']['EXTCONF']['backend']['loginProviders'][1613676682] = [
            'provider'   => \FSG\Oidc\LoginProvider\OpenIDConnectSignInProvider::class,
            'sorting'    => 75,
            'icon-class' => 'fa-openid',
            'label'      => 'LLL:EXT:t3oidc/Resources/Private/Language/locallang.xlf:backend.login.switch.label',
        ];
    }

    // Require 3rd-party libraries, in case TYPO3 does not run in composer mode
    $pharFileName = \TYPO3\CMS\Core\Utility\ExtensionManagementUtility::extPath($extKey)
                    . 'Libraries/league-oauth2-client.phar';
    if (is_file($pharFileName)) {
        @include 'phar://' . $pharFileName . '/vendor/autoload.php';
    }
})('t3oidc');
