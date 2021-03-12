<?php

namespace FSG\Oidc\Tests\Unit\Service;

use FSG\Oidc\Domain\Model\Dto\ExtensionConfiguration;
use FSG\Oidc\Service\AuthenticationService;
use PHPUnit\Framework\MockObject\MockObject;
use Prophecy\PhpUnit\ProphecyTrait;
use Prophecy\Prophecy\ObjectProphecy;
use Psr\Log\NullLogger;
use ReflectionProperty;
use TYPO3\CMS\Core\Authentication\AbstractUserAuthentication;
use TYPO3\TestingFramework\Core\AccessibleObjectInterface;
use TYPO3\TestingFramework\Core\Unit\UnitTestCase;

/**
 * Class AuthenticationServiceTest
 */
class AuthenticationServiceTest extends UnitTestCase
{
    use ProphecyTrait;

    /**
     * @var ExtensionConfiguration | MockObject | AccessibleObjectInterface
     */
    private $extensionConfigurationMock;

    /**
     * Sets up this test case.
     */
    protected function setUp(): void
    {
        parent::setUp();

        $this->resetSingletonInstances = true;
    }

    /**
     * @test
     * @return AuthenticationService | MockObject | AccessibleObjectInterface
     */
    public function expect100IfServiceIsNotResponsible()
    {
        /** @var AuthenticationService | MockObject | AccessibleObjectInterface $authenticationServiceMock */
        $authenticationServiceMock = $this->getAccessibleMock(AuthenticationService::class, ['dummy'], [], '', false);
        $authenticationServiceMock->_set('login', ['responsible' => false]);

        self::assertSame(100, $authenticationServiceMock->authUser([]));

        return $authenticationServiceMock;
    }

    /**
     * @test
     * @depends expect100IfServiceIsNotResponsible
     *
     * @param AuthenticationService | MockObject | AccessibleObjectInterface $authenticationServiceMock
     *
     * @return AuthenticationService | MockObject | AccessibleObjectInterface
     */
    public function expect100IfNoOIDCIdentifier($authenticationServiceMock)
    {
        $authenticationServiceMock->_set('login', ['responsible' => true]);

        self::assertSame(100, $authenticationServiceMock->authUser([]));

        return $authenticationServiceMock;
    }

    /**
     * @test
     * @depends expect100IfNoOIDCIdentifier
     *
     * @param AuthenticationService | MockObject | AccessibleObjectInterface $authenticationServiceMock
     *
     * @return AuthenticationService | MockObject | AccessibleObjectInterface
     */
    public function expect100IfOIDCIdentifierDoesNotMatchUserInfoIdentifier($authenticationServiceMock)
    {
        /** @var ExtensionConfiguration | MockObject | AccessibleObjectInterface $extensionConfigurationMock */
        $extensionConfigurationMock = $this->getAccessibleMock(ExtensionConfiguration::class, ['dummy'], [], '', false);
        $extensionConfigurationMock->_set('tokenUserIdentifier', 'sub');

        $authenticationServiceMock->_set('extensionConfiguration', $extensionConfigurationMock);

        $reflectionProperty = new ReflectionProperty(AuthenticationService::class, 'userInfo');
        $reflectionProperty->setAccessible(true);
        $reflectionProperty->setValue($authenticationServiceMock, ['sub' => 'foo']);

        self::assertSame(100, $authenticationServiceMock->authUser(['oidc_identifier' => 'bar']));

        return $authenticationServiceMock;
    }

    /**
     * @test
     * @depends expect100IfOIDCIdentifierDoesNotMatchUserInfoIdentifier
     *
     * @param AuthenticationService | MockObject | AccessibleObjectInterface $authenticationServiceMock
     *
     * @return AuthenticationService|MockObject|AccessibleObjectInterface
     */
    public function expect0IfDomainLockDoesNotMatch($authenticationServiceMock)
    {
        /** @var AbstractUserAuthentication | ObjectProphecy $pObjProphecy */
        $pObjProphecy = $this->prophesize(AbstractUserAuthentication::class);
        /** @var NullLogger | ObjectProphecy $pObjProphecy */
        $loggerProphecy = $this->prophesize(NullLogger::class);

        $authenticationServiceMock->_set('pObj', $pObjProphecy->reveal());
        $authenticationServiceMock->_set('logger', $loggerProphecy->reveal());
        $authenticationServiceMock->_set('loginType', 'BE');
        $authenticationServiceMock->_set('authInfo', ['HTTP_HOST' => 'example.com']);
        $authenticationServiceMock->_set('db_user', ['username_column' => 'username']);

        $user = [
            'username'        => 'Foo',
            'lockToDomain'    => 'not.example.com',
            'oidc_identifier' => 'foo',
        ];
        self::assertSame(0, $authenticationServiceMock->authUser($user));

        return $authenticationServiceMock;
    }

    /**
     * @test
     * @depends expect0IfDomainLockDoesNotMatch
     *
     * @param AuthenticationService | MockObject | AccessibleObjectInterface $authenticationServiceMock
     *
     * @return  AuthenticationService | MockObject | AccessibleObjectInterface
     */
    public function expect200IfDomainLockDoesMatch($authenticationServiceMock)
    {
        $user = [
            'username'        => 'Foo',
            'lockToDomain'    => 'example.com',
            'oidc_identifier' => 'foo',
        ];
        self::assertSame(200, $authenticationServiceMock->authUser($user));

        return $authenticationServiceMock;
    }

    /**
     * @test
     * @depends expect200IfDomainLockDoesMatch
     *
     * @param AuthenticationService | MockObject | AccessibleObjectInterface $authenticationServiceMock
     */
    public function expect200IfNoDomainLock($authenticationServiceMock): void
    {
        $user = [
            'username'        => 'Foo',
            'lockToDomain'    => '',
            'oidc_identifier' => 'foo',
        ];
        self::assertSame(200, $authenticationServiceMock->authUser($user));
    }
}
