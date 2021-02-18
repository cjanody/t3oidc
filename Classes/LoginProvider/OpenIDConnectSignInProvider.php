<?php

declare(strict_types=1);

namespace FSG\Oidc\LoginProvider;

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

use FSG\Oidc\Error\ConfigurationException;
use FSG\Oidc\Service\StatusService;
use TYPO3\CMS\Backend\Controller\LoginController;
use TYPO3\CMS\Backend\LoginProvider\LoginProviderInterface;
use TYPO3\CMS\Core\Page\PageRenderer;
use TYPO3\CMS\Core\Utility\GeneralUtility;
use TYPO3\CMS\Fluid\View\StandaloneView;

/**
 * Class OpenIDConnectSignInProvider
 */
class OpenIDConnectSignInProvider implements LoginProviderInterface
{
    /**
     * @param StandaloneView  $view
     * @param PageRenderer    $pageRenderer
     * @param LoginController $loginController
     */
    public function render(StandaloneView $view, PageRenderer $pageRenderer, LoginController $loginController): void
    {
        $view->setTemplatePathAndFilename(
            GeneralUtility::getFileAbsFileName('EXT:t3oidc/Resources/Private/Templates/BackendLogin.html')
        );

        try {
            StatusService::isEnabled('BE');
        } catch (ConfigurationException $e) {
            $view->assign('error', $e);
        }
    }
}
