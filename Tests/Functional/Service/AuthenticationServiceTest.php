<?php

namespace FSG\Oidc\Tests\Functional\Service;

use DateTime;
use Doctrine\DBAL\DBALException;
use Doctrine\DBAL\Schema\SchemaException;
use FSG\Oidc\Domain\Model\Dto\ExtensionConfiguration;
use FSG\Oidc\Service\AuthenticationService;
use PHPUnit\Framework\MockObject\MockObject;
use Prophecy\PhpUnit\ProphecyTrait;
use Prophecy\Prophecy\ObjectProphecy;
use Psr\Log\NullLogger;
use ReflectionException;
use ReflectionMethod;
use ReflectionProperty;
use RuntimeException;
use TYPO3\CMS\Core\Authentication\BackendUserAuthentication;
use TYPO3\CMS\Core\Database\Schema\Exception\StatementException;
use TYPO3\CMS\Core\Database\Schema\Exception\UnexpectedSignalReturnValueTypeException;
use TYPO3\CMS\Core\Database\Schema\SchemaMigrator;
use TYPO3\CMS\Core\Database\Schema\SqlReader;
use TYPO3\CMS\Core\Utility\GeneralUtility;
use TYPO3\TestingFramework\Core\AccessibleObjectInterface;
use TYPO3\TestingFramework\Core\Exception;
use TYPO3\TestingFramework\Core\Functional\FunctionalTestCase;

/**
 * Testcase for class FSG\Oidc\Service\AuthenticationService
 */
class AuthenticationServiceTest extends FunctionalTestCase
{
    use ProphecyTrait;

    /**
     * @var AuthenticationService|MockObject|AccessibleObjectInterface
     */
    protected $authenticationService;

    /**
     * @var ExtensionConfiguration|ObjectProphecy
     */
    protected $extensionConfigurationProphesize;

    /**
     * @var array<string, string>
     */
    protected array $beDbUser = [
        'table'            => 'be_users',
        'username_column'  => 'oidc_identifier',
        'check_pid_clause' => '',
        'enable_clause'    => '',
    ];

    /**
     * @throws DBALException
     * @throws Exception
     * @throws SchemaException
     * @throws StatementException
     * @throws UnexpectedSignalReturnValueTypeException
     */
    protected function setUp(): void
    {
        $this->extensionConfigurationProphesize = $this->prophesize(ExtensionConfiguration::class);
        $this->extensionConfigurationProphesize->getTokenUserIdentifier()->willReturn('sub');
        $this->extensionConfigurationProphesize->isUnDeleteBackendUsers()->willReturn(false);
        $this->extensionConfigurationProphesize->isReEnableBackendUsers()->willReturn(false);
        $this->extensionConfigurationProphesize->isBackendUserMustExistLocally()->willReturn(false);

        $this->authenticationService = $this->getAccessibleMock(AuthenticationService::class, ['dummy'], [], '', false);
        $this->authenticationService->_set('extensionConfiguration', $this->extensionConfigurationProphesize->reveal());
        $this->authenticationService->_set('logger', new NullLogger());
        $this->authenticationService->_set('db_user', $this->beDbUser);
        $this->authenticationService->_set('login', ['status' => 'login', 'responsible' => true]);
        $this->authenticationService->_set('authInfo', ['loginType' => 'BE']);

        parent::setUp();

        $this->authenticationService->pObj = new BackendUserAuthentication();
        $this->importExtTablesDefinition();
        $this->importDataSet(ORIGINAL_ROOT . 'typo3conf/ext/t3oidc/Tests/Functional/Fixtures/be_users.xml');
    }

    /**
     * Imports the ext_tables.sql definition as done by the install tool.
     *
     * @throws DBALException
     * @throws SchemaException
     * @throws StatementException
     * @throws UnexpectedSignalReturnValueTypeException
     */
    protected function importExtTablesDefinition(): void
    {
        $schemaMigrationService = GeneralUtility::makeInstance(SchemaMigrator::class);
        $sqlReader              = GeneralUtility::makeInstance(SqlReader::class);
        $sqlCode                = file_get_contents(ORIGINAL_ROOT . 'typo3conf/ext/t3oidc/ext_tables.sql');

        $createTableStatements = $sqlReader->getCreateTableStatementArray($sqlCode);

        $updateResult     = $schemaMigrationService->install($createTableStatements);
        $failedStatements = array_filter($updateResult);
        $result           = [];
        foreach ($failedStatements as $query => $error) {
            $result[] = 'Query "' . $query . '" returned "' . $error . '"';
        }

        if (!empty($result)) {
            throw new RuntimeException(implode("\n", $result), 1615316197);
        }

        $insertStatements = $sqlReader->getInsertStatementArray($sqlCode);
        $schemaMigrationService->importStaticData($insertStatements);
    }

    /**
     * @test
     */
    public function expectNullIfLoginStatusIsNotEqualToLoginTypeLogin(): void
    {
        $this->authenticationService->login['status'] = 'foo';

        $reflectionProperty = new ReflectionProperty(AuthenticationService::class, 'userInfo');
        $reflectionProperty->setAccessible(true);
        $reflectionProperty->setValue($this->authenticationService, ['sub' => '']);

        $result = $this->authenticationService->getUser();
        self::assertNull($result);
    }

    /**
     * @test
     */
    public function expectNullIfServiceIsNotResponsible(): void
    {
        $this->authenticationService->login['responsible'] = false;

        $result = $this->authenticationService->getUser();
        self::assertNull($result);
    }

    /**
     * @test
     */
    public function expectNullIfUserInfoIdentifierIsNotSet(): void
    {
        $reflectionProperty = new ReflectionProperty(AuthenticationService::class, 'userInfo');
        $reflectionProperty->setAccessible(true);
        $reflectionProperty->setValue($this->authenticationService, []);

        $result = $this->authenticationService->getUser();
        self::assertNull($result);
    }

    /**
     * @test
     */
    public function expectNotDeletedUser(): void
    {
        $reflectionProperty = new ReflectionProperty(AuthenticationService::class, 'userInfo');
        $reflectionProperty->setAccessible(true);
        $reflectionProperty->setValue($this->authenticationService, ['sub' => 'Foo']);

        $result = $this->authenticationService->getUser();
        self::assertSame('Foo', $result['oidc_identifier']);
        self::assertSame(0, (int)$result['deleted']);
    }

    /**
     * @test
     */
    public function expectNullIfUserIsNotFound(): void
    {
        $reflectionProperty = new ReflectionProperty(AuthenticationService::class, 'userInfo');
        $reflectionProperty->setAccessible(true);
        $reflectionProperty->setValue($this->authenticationService, ['sub' => 'Bar']);

        $result = $this->authenticationService->getUser();
        self::assertNull($result);
    }

    /**
     * @test
     * @throws ReflectionException
     */
    public function expectUpdatedActiveBEUser(): void
    {
        $reflectionMethod = new ReflectionMethod(AuthenticationService::class, 'insertOrUpdateUser');
        $reflectionMethod->setAccessible(true);

        $reflectionProperty = new ReflectionProperty(AuthenticationService::class, 'userInfo');
        $reflectionProperty->setAccessible(true);
        $reflectionProperty->setValue(
            $this->authenticationService,
            ['sub' => 'Foo', 'name' => 'Foo FOO', 'email' => 'foo@foo.com']
        );

        $user = $reflectionMethod->invoke($this->authenticationService);

        $endtime = new \DateTime('today +3 month');
        self::assertSame($endtime->getTimestamp(), $user['endtime']);
        self::assertSame('Foo FOO', $user['realName']);
        self::assertSame('foo@foo.com', $user['email']);
    }

    /**
     * @test
     * @throws ReflectionException
     */
    public function expectNoBEUserIfDisableAndOrDeleted(): void
    {
        $reflectionMethod = new ReflectionMethod(AuthenticationService::class, 'insertOrUpdateUser');
        $reflectionMethod->setAccessible(true);

        // Authentication of a deleted backend user
        $reflectionProperty = new ReflectionProperty(AuthenticationService::class, 'userInfo');
        $reflectionProperty->setAccessible(true);
        $reflectionProperty->setValue(
            $this->authenticationService,
            ['sub' => 'Bar', 'name' => 'Bar BAR', 'email' => 'bar@bar.com']
        );

        self::assertEmpty($reflectionMethod->invoke($this->authenticationService));

        // Authentication of a disabled backend user
        $reflectionProperty = new ReflectionProperty(AuthenticationService::class, 'userInfo');
        $reflectionProperty->setAccessible(true);
        $reflectionProperty->setValue(
            $this->authenticationService,
            ['sub' => 'FooBar', 'name' => 'Foo BAR', 'email' => 'foobar@foobar.com']
        );

        self::assertEmpty($reflectionMethod->invoke($this->authenticationService));

        // Authentication of a deleted and disabled backend user
        $reflectionProperty = new ReflectionProperty(AuthenticationService::class, 'userInfo');
        $reflectionProperty->setAccessible(true);
        $reflectionProperty->setValue(
            $this->authenticationService,
            ['sub' => 'BarFoo', 'name' => 'Bar Foo', 'email' => 'barfoo@barfoo.com']
        );

        self::assertEmpty($reflectionMethod->invoke($this->authenticationService));
    }

    /**
     * @test
     * @throws ReflectionException
     */
    public function expectUpdatedBEUserIfDisableAndOrDeleted(): void
    {
        $endtime = new DateTime('today +3 month');

        $reflectionMethod = new ReflectionMethod(AuthenticationService::class, 'insertOrUpdateUser');
        $reflectionMethod->setAccessible(true);

        // Authentication of a deleted backend user
        $this->extensionConfigurationProphesize->isUnDeleteBackendUsers()->willReturn(true);
        $this->authenticationService->_set('extensionConfiguration', $this->extensionConfigurationProphesize->reveal());

        $reflectionProperty = new ReflectionProperty(AuthenticationService::class, 'userInfo');
        $reflectionProperty->setAccessible(true);
        $reflectionProperty->setValue(
            $this->authenticationService,
            ['sub' => 'Bar', 'name' => 'Bar BAR', 'email' => 'bar@bar.com']
        );

        $user = $reflectionMethod->invoke($this->authenticationService);
        self::assertSame($endtime->getTimestamp(), $user['endtime']);
        self::assertSame('Bar BAR', $user['realName']);
        self::assertSame('bar@bar.com', $user['email']);

        // Authentication of a deleted and disabled backend user
        $this->extensionConfigurationProphesize->isReEnableBackendUsers()->willReturn(true);
        $this->authenticationService->_set('extensionConfiguration', $this->extensionConfigurationProphesize->reveal());

        $reflectionProperty = new ReflectionProperty(AuthenticationService::class, 'userInfo');
        $reflectionProperty->setAccessible(true);
        $reflectionProperty->setValue(
            $this->authenticationService,
            ['sub' => 'BarFoo', 'name' => 'Bar Foo', 'email' => 'barfoo@barfoo.com']
        );

        $user = $reflectionMethod->invoke($this->authenticationService);
        self::assertSame($endtime->getTimestamp(), $user['endtime']);
        self::assertSame('Bar Foo', $user['realName']);
        self::assertSame('barfoo@barfoo.com', $user['email']);

        // Authentication of a disabled backend user
        $this->extensionConfigurationProphesize->isUnDeleteBackendUsers()->willReturn(false);
        $this->authenticationService->_set('extensionConfiguration', $this->extensionConfigurationProphesize->reveal());

        $reflectionProperty = new ReflectionProperty(AuthenticationService::class, 'userInfo');
        $reflectionProperty->setAccessible(true);
        $reflectionProperty->setValue(
            $this->authenticationService,
            ['sub' => 'FooBar', 'name' => 'Foo BAR', 'email' => 'foobar@foobar.com']
        );

        $user = $reflectionMethod->invoke($this->authenticationService);
        self::assertSame($endtime->getTimestamp(), $user['endtime']);
        self::assertSame('Foo BAR', $user['realName']);
        self::assertSame('foobar@foobar.com', $user['email']);
    }

    /**
     * @test
     * @throws ReflectionException
     */
    public function expectInsertedBEUser(): void
    {
        $endtime = new DateTime('today +3 month');

        $reflectionMethod = new ReflectionMethod(AuthenticationService::class, 'insertOrUpdateUser');
        $reflectionMethod->setAccessible(true);

        // Authentication of a new backend user
        $this->extensionConfigurationProphesize->isEnableBackendAuthentication()->willReturn(true);
        $this->authenticationService->_set('extensionConfiguration', $this->extensionConfigurationProphesize->reveal());

        $reflectionProperty = new ReflectionProperty(AuthenticationService::class, 'userInfo');
        $reflectionProperty->setAccessible(true);
        $reflectionProperty->setValue(
            $this->authenticationService,
            ['sub' => 'NewUser', 'name' => 'New USER', 'email' => 'new@user.com']
        );

        $user = $reflectionMethod->invoke($this->authenticationService);
        self::assertSame($endtime->getTimestamp(), $user['endtime']);
        self::assertSame('New USER', $user['realName']);
        self::assertSame('new@user.com', $user['email']);
    }
}
