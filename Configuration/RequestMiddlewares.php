<?php

declare(strict_types=1);

return [
    'frontend' => [
        'fsg/oidc/callback' => [
            'target' => \FSG\Oidc\Middleware\CallbackMiddleware::class,
            'after' => [
                'typo3/cms-frontend/authentication',
            ],
            'before' => [
                'typo3/cms-frontend/base-redirect-resolver',
            ],
        ]
    ],
];
