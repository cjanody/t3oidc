<?php

declare(strict_types=1);

namespace FSG\Oidc\Middleware;

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

use FSG\Oidc\LoginProvider\OpenIDConnectSignInProvider;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use TYPO3\CMS\Core\Http\RedirectResponse;
use TYPO3\CMS\Core\Utility\GeneralUtility;

class CallbackMiddleware implements MiddlewareInterface
{
    const PATH = '/oidc/callback';

    const BACKEND_URI = '%s/typo3/?loginProvider=%d&code=%s&state=%s';

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if (strpos($request->getUri()->getPath(), self::PATH) === false) {
            // Middleware is not responsible for given request
            return $handler->handle($request);
        }

        return $this->handleBackendCallback($request);
    }

    protected function handleBackendCallback(ServerRequestInterface $request): RedirectResponse
    {
        $queryParams = $request->getQueryParams();

        $redirectUri = sprintf(
            self::BACKEND_URI,
            GeneralUtility::getIndpEnv('TYPO3_REQUEST_HOST'),
            OpenIDConnectSignInProvider::LOGIN_PROVIDER,
            $queryParams['code'],
            $queryParams['state']
        );

        // Add error parameters to backend uri if exists
        if (!empty(GeneralUtility::_GET('error')) && !empty(GeneralUtility::_GET('error_description'))) {
            $redirectUri .= sprintf(
                '&error=%s&error_description=%s',
                GeneralUtility::_GET('error'),
                GeneralUtility::_GET('error_description')
            );
        }

        return new RedirectResponse($redirectUri, 302);
    }
}
