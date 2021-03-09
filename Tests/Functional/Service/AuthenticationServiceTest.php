<?php

namespace FSG\Oidc\Tests\Functional\Service;

use Doctrine\DBAL\DBALException;
use Doctrine\DBAL\Schema\SchemaException;
use FSG\Oidc\Domain\Model\Dto\ExtensionConfiguration;
use FSG\Oidc\Service\AuthenticationService;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Log\NullLogger;
use ReflectionProperty;
use RuntimeException;
use TYPO3\CMS\Core\Authentication\BackendUserAuthentication;
use TYPO3\CMS\Core\Authentication\LoginType;
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
    /**
     * @var AuthenticationService | MockObject | AccessibleObjectInterface
     */
    protected $subject;

    /**
     * @var array<string, string>
     */
    protected array $beDbUser = [
        'table'            => 'be_users',
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
        /** @var ExtensionConfiguration | MockObject | AccessibleObjectInterface $extensionConfigurationMock */
        $extensionConfigurationMock = $this->getAccessibleMock(ExtensionConfiguration::class, ['dummy'], [], '', false);
        $extensionConfigurationMock->_set('tokenUserIdentifier', 'sub');

        /** @var AuthenticationService | MockObject | AccessibleObjectInterface $authenticationService */
        $authenticationService = $this->getAccessibleMock(AuthenticationService::class, ['dummy'], [], '', false);
        $authenticationService->_set('extensionConfiguration', $extensionConfigurationMock);
        $authenticationService->setLogger(new NullLogger());

        parent::setUp();

        $authenticationService->pObj = new BackendUserAuthentication();
        $this->subject               = $authenticationService;
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
     * @return AuthenticationService | MockObject | AccessibleObjectInterface
     */
    public function expectNullIfLoginStatusIsNotEqualToLoginTypeLogin()
    {
        $this->subject->db_user              = $this->beDbUser;
        $this->subject->login['status']      = 'foo';
        $this->subject->login['responsible'] = true;

        $reflectionProperty = new ReflectionProperty(AuthenticationService::class, 'userInfo');
        $reflectionProperty->setAccessible(true);
        $reflectionProperty->setValue($this->subject, ['sub' => '']);

        $result = $this->subject->getUser();
        self::assertNull($result);

        return $this->subject;
    }

    /**
     * @test
     * @depends expectNullIfLoginStatusIsNotEqualToLoginTypeLogin
     *
     * @param AuthenticationService | MockObject | AccessibleObjectInterface $subject
     *
     * @return AuthenticationService | MockObject | AccessibleObjectInterface
     */
    public function expectNullIfServiceIsNotResponsible($subject)
    {
        $subject->login['status']      = LoginType::LOGIN;
        $subject->login['responsible'] = false;

        $result = $subject->getUser();
        self::assertNull($result);

        return $subject;
    }

    /**
     * @test
     * @depends expectNullIfServiceIsNotResponsible
     *
     * @param AuthenticationService | MockObject | AccessibleObjectInterface $subject
     *
     * @return AuthenticationService | MockObject | AccessibleObjectInterface
     */
    public function expectNullIfUserInfoIdentifierIsNotSet($subject)
    {
        $subject->login['responsible'] = true;

        $reflectionProperty = new ReflectionProperty(AuthenticationService::class, 'userInfo');
        $reflectionProperty->setAccessible(true);
        $reflectionProperty->setValue($subject, []);

        $result = $subject->getUser();
        self::assertNull($result);

        return $subject;
    }

    /**
     * @test
     * @depends expectNullIfUserInfoIdentifierIsNotSet
     *
     * @param AuthenticationService | MockObject | AccessibleObjectInterface $subject
     */
    public function expectNotDeletedUser($subject): void
    {
        $reflectionProperty = new ReflectionProperty(AuthenticationService::class, 'userInfo');
        $reflectionProperty->setAccessible(true);
        $reflectionProperty->setValue($subject, ['sub' => 'Foo']);

        $result = $subject->getUser();
        self::assertSame('Foo', $result['oidc_identifier']);
        self::assertSame(0, (int)$result['deleted']);
    }

    /**
     * @test
     * @depends expectNullIfUserInfoIdentifierIsNotSet
     *
     * @param AuthenticationService | MockObject | AccessibleObjectInterface $subject
     */
    public function expectNullIfUserIsNotFound($subject): void
    {
        $reflectionProperty = new ReflectionProperty(AuthenticationService::class, 'userInfo');
        $reflectionProperty->setAccessible(true);
        $reflectionProperty->setValue($subject, ['sub' => 'Bar']);

        $result = $subject->getUser();
        self::assertNull($result);
    }
}
