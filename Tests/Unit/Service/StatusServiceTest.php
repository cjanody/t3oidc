<?php

namespace FSG\Oidc\Tests\Unit\Service;

use FSG\Oidc\Domain\Model\Dto\ExtensionConfiguration;
use FSG\Oidc\Error\ConfigurationException;
use FSG\Oidc\Error\HTTPSConnectionException;
use FSG\Oidc\Service\StatusService;
use TYPO3\CMS\Core\Http\NormalizedParams;
use TYPO3\CMS\Core\Http\ServerRequest;
use TYPO3\CMS\Core\Utility\GeneralUtility;
use TYPO3\TestingFramework\Core\Unit\UnitTestCase;
use UnexpectedValueException;

/**
 * Class StatusServiceTest
 */
class StatusServiceTest extends UnitTestCase
{
    /**
     * @var ServerRequest
     */
    private ServerRequest $request;

    /**
     * Sets up this test case.
     */
    protected function setUp(): void
    {
        parent::setUp();

        $this->resetSingletonInstances = true;
        $this->request                 = new ServerRequest('/');
    }

    /**
     * Initialize TYPO3 request to run tests
     *
     * @param bool $https
     */
    private function initializeRequest(bool $https = true): void
    {
        $GLOBALS['TYPO3_REQUEST'] = $this->request->withAttribute(
            'normalizedParams',
            new NormalizedParams(['HTTPS' => $https], [], '', '')
        );
    }

    /**
     * Test if the backend authentication is disabled by default
     *
     * @test
     */
    public function expectFalseForIsEnableBackendAuthentication(): void
    {
        $this->initializeRequest();

        $settings = [
            'clientId'            => 'foo',
            'clientSecret'        => 'bar',
            'clientScopes'        => 'foo',
            'endpointAuthorize'   => 'bar',
            'endpointToken'       => 'foo',
            'endpointUserInfo'    => 'bar',
            'tokenUserIdentifier' => 'foo',
        ];

        $extensionConfigurationMock = $this->getAccessibleMock(ExtensionConfiguration::class, ['dummy'], [], '', false);
        foreach ($settings as $key => $value) {
            $extensionConfigurationMock->_set($key, $value);
        }

        /**
         * @var ExtensionConfiguration $extensionConfigurationMock
         */
        GeneralUtility::setSingletonInstance(ExtensionConfiguration::class, $extensionConfigurationMock);

        self::assertFalse(StatusService::isEnabled('BE'));
    }

    /**
     * Test if the backend authentication is disabled by default
     *
     * @test
     */
    public function expectTrueForIsEnableBackendAuthentication(): void
    {
        $this->initializeRequest();

        $settings = [
            'clientId'                    => 'foo',
            'clientSecret'                => 'bar',
            'clientScopes'                => 'foo',
            'endpointAuthorize'           => 'bar',
            'endpointToken'               => 'foo',
            'endpointUserInfo'            => 'bar',
            'tokenUserIdentifier'         => 'foo',
            'enableBackendAuthentication' => true,
        ];

        $extensionConfigurationMock = $this->getAccessibleMock(ExtensionConfiguration::class, ['dummy'], [], '', false);
        foreach ($settings as $key => $value) {
            $extensionConfigurationMock->_set($key, $value);
        }

        /**
         * @var ExtensionConfiguration $extensionConfigurationMock
         */
        GeneralUtility::setSingletonInstance(ExtensionConfiguration::class, $extensionConfigurationMock);

        self::assertTrue(StatusService::isEnabled('BE'));
    }

    /**
     * Test if the right exception is thrown for an invalid mode
     *
     * @test
     */
    public function expectExceptionForInvalidMode(): void
    {
        $this->expectException(UnexpectedValueException::class);
        StatusService::isEnabled('FOO');
    }

    /**
     * Test if the right exception code is return for a none HTTPS environment
     *
     * @test
     */
    public function expectExceptionForNoneHTTPSEnvironment(): void
    {
        $this->initializeRequest(false);

        $this->expectException(HTTPSConnectionException::class);
        $this->expectExceptionCode(1613676691);
        StatusService::isEnabled('BE');
    }

    /**
     * Test if the right exception code is return for no client ID configured
     *
     * @test
     */
    public function expectExceptionForNoClientIDConfigured(): void
    {
        $this->initializeRequest();

        $settings = [
            'clientId' => '',
        ];

        $extensionConfigurationMock = $this->getAccessibleMock(ExtensionConfiguration::class, ['dummy'], [], '', false);
        foreach ($settings as $key => $value) {
            $extensionConfigurationMock->_set($key, $value);
        }

        /**
         * @var ExtensionConfiguration $extensionConfigurationMock
         */
        GeneralUtility::setSingletonInstance(ExtensionConfiguration::class, $extensionConfigurationMock);

        $this->expectException(ConfigurationException::class);
        $this->expectExceptionCode(1613676692);
        StatusService::isEnabled('BE');
    }

    /**
     * Test if the right exception code is return for no client secret configured
     *
     * @test
     */
    public function expectExceptionForNoClientSecretConfigured(): void
    {
        $this->initializeRequest();

        $settings = [
            'clientId'     => 'foo',
            'clientSecret' => '',
        ];

        $extensionConfigurationMock = $this->getAccessibleMock(ExtensionConfiguration::class, ['dummy'], [], '', false);
        foreach ($settings as $key => $value) {
            $extensionConfigurationMock->_set($key, $value);
        }

        /**
         * @var ExtensionConfiguration $extensionConfigurationMock
         */
        GeneralUtility::setSingletonInstance(ExtensionConfiguration::class, $extensionConfigurationMock);

        $this->expectException(ConfigurationException::class);
        $this->expectExceptionCode(1613676693);
        StatusService::isEnabled('BE');
    }

    /**
     * Test if the right exception code is return for no client scope configured
     *
     * @test
     */
    public function expectExceptionForNoClientScopeConfigured(): void
    {
        $this->initializeRequest();

        $settings = [
            'clientId'     => 'foo',
            'clientSecret' => 'bar',
            'clientScopes' => '',
        ];

        $extensionConfigurationMock = $this->getAccessibleMock(ExtensionConfiguration::class, ['dummy'], [], '', false);
        foreach ($settings as $key => $value) {
            $extensionConfigurationMock->_set($key, $value);
        }

        /**
         * @var ExtensionConfiguration $extensionConfigurationMock
         */
        GeneralUtility::setSingletonInstance(ExtensionConfiguration::class, $extensionConfigurationMock);

        $this->expectException(ConfigurationException::class);
        $this->expectExceptionCode(1613676694);
        StatusService::isEnabled('BE');
    }

    /**
     * Test if the right exception code is return for no authorize endpoint configured
     *
     * @test
     */
    public function expectExceptionForNoAuthorizeEndpointConfigured(): void
    {
        $this->initializeRequest();

        $settings = [
            'clientId'          => 'foo',
            'clientSecret'      => 'bar',
            'clientScopes'      => 'foo',
            'endpointAuthorize' => '',
        ];

        $extensionConfigurationMock = $this->getAccessibleMock(ExtensionConfiguration::class, ['dummy'], [], '', false);
        foreach ($settings as $key => $value) {
            $extensionConfigurationMock->_set($key, $value);
        }

        /**
         * @var ExtensionConfiguration $extensionConfigurationMock
         */
        GeneralUtility::setSingletonInstance(ExtensionConfiguration::class, $extensionConfigurationMock);

        $this->expectException(ConfigurationException::class);
        $this->expectExceptionCode(1613676695);
        StatusService::isEnabled('BE');
    }

    /**
     * Test if the right exception code is return for no token endpoint configured
     *
     * @test
     */
    public function expectExceptionForNoTokenEndpointConfigured(): void
    {
        $this->initializeRequest();

        $settings = [
            'clientId'          => 'foo',
            'clientSecret'      => 'bar',
            'clientScopes'      => 'foo',
            'endpointAuthorize' => 'bar',
            'endpointToken'     => '',
        ];

        $extensionConfigurationMock = $this->getAccessibleMock(
            ExtensionConfiguration::class,
            ['dummy'],
            [],
            'ExtensionConfigurationMock',
            false
        );
        foreach ($settings as $key => $value) {
            $extensionConfigurationMock->_set($key, $value);
        }

        /**
         * @var ExtensionConfiguration $extensionConfigurationMock
         */
        GeneralUtility::setSingletonInstance(ExtensionConfiguration::class, $extensionConfigurationMock);

        $this->expectException(ConfigurationException::class);
        $this->expectExceptionCode(1613676696);
        StatusService::isEnabled('BE');
    }

    /**
     * Test if the right exception code is return for no user info endpoint configured
     *
     * @test
     */
    public function expectExceptionForNoUserInfoEndpointConfigured(): void
    {
        $this->initializeRequest();

        $settings = [
            'clientId'          => 'foo',
            'clientSecret'      => 'bar',
            'clientScopes'      => 'foo',
            'endpointAuthorize' => 'bar',
            'endpointToken'     => 'foo',
            'endpointUserInfo'  => '',
        ];

        $extensionConfigurationMock = $this->getAccessibleMock(ExtensionConfiguration::class, ['dummy'], [], '', false);
        foreach ($settings as $key => $value) {
            $extensionConfigurationMock->_set($key, $value);
        }

        /**
         * @var ExtensionConfiguration $extensionConfigurationMock
         */
        GeneralUtility::setSingletonInstance(ExtensionConfiguration::class, $extensionConfigurationMock);

        $this->expectException(ConfigurationException::class);
        $this->expectExceptionCode(1613676697);
        StatusService::isEnabled('BE');
    }

    /**
     * Test if the right exception code is return for no token user identifier configured
     *
     * @test
     */
    public function expectExceptionForNoTokenUserIdentifierConfigured(): void
    {
        $this->initializeRequest();

        $settings = [
            'clientId'            => 'foo',
            'clientSecret'        => 'bar',
            'clientScopes'        => 'foo',
            'endpointAuthorize'   => 'bar',
            'endpointToken'       => 'foo',
            'endpointUserInfo'    => 'bar',
            'tokenUserIdentifier' => '',
        ];

        $extensionConfigurationMock = $this->getAccessibleMock(ExtensionConfiguration::class, ['dummy'], [], '', false);
        foreach ($settings as $key => $value) {
            $extensionConfigurationMock->_set($key, $value);
        }

        /**
         * @var ExtensionConfiguration $extensionConfigurationMock
         */
        GeneralUtility::setSingletonInstance(ExtensionConfiguration::class, $extensionConfigurationMock);

        $this->expectException(ConfigurationException::class);
        $this->expectExceptionCode(1613676698);
        StatusService::isEnabled('BE');
    }
}
