<?php
declare(strict_types=1);
namespace ParagonIE\CipherSweet\KeyProvider\Tests;

use Aws\Kms\KmsClient;
use ParagonIE\Certainty\RemoteFetch;
use ParagonIE\CipherSweet\Backend\BoringCrypto;
use ParagonIE\CipherSweet\Backend\FIPSCrypto;
use ParagonIE\CipherSweet\CipherSweet;
use ParagonIE\CipherSweet\Contract\BackendInterface;
use ParagonIE\CipherSweet\EncryptedRow;
use ParagonIE\CipherSweet\Exception\CipherSweetException;
use ParagonIE\CipherSweet\KeyProvider\KmsKeyProvider;
use ParagonIE\CipherSweet\KeyProvider\MultiTenantKmsKeyProvider;
use PHPUnit\Framework\TestCase;

/**
 * @covers MultiTenantKmsKeyProvider
 */
class MultiTenantKmsKeyProviderTest extends TestCase
{
    public function getKmsProvider(
        BackendInterface $backend
    ): KmsKeyProvider {
        $remoteFetch = new RemoteFetch(dirname(__DIR__) . '/data');
        $latestBundle = $remoteFetch->getLatestBundle()->getFilePath();
        $jsonFile = dirname(__DIR__) . '/data/kms.json';
        if (is_readable($jsonFile)) {
            $config = json_decode(file_get_contents($jsonFile), true);
        } else {
            $config = [
                'key-arn' => 'arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f',
                'region' => 'us-west-2'
            ];
        }
        $kmsClient = new KmsClient([
            'profile' => 'default',
            'region' => $config['region'],
            'http' => ['verify' => $latestBundle]
        ]);
        return KmsKeyProvider::generate(
            $kmsClient,
            $backend,
            $config['key-arn']
        );
    }

    public function getMultiTenantProvider(BackendInterface $backend): MultiTenantKmsKeyProvider
    {
        return new MultiTenantKmsKeyProvider([], null, $backend);
    }

    public function keyProvider(): array
    {
        return [
            [$this->getMultiTenantProvider(new FIPSCrypto())],
            [$this->getMultiTenantProvider(new BoringCrypto())],
        ];
    }

    /**
     * @dataProvider keyProvider
     */
    public function testMultiTenancy(MultiTenantKmsKeyProvider $multi): void
    {
        $multi->addTenant('foo', $this->getKmsProvider($multi->getBackend()));
        $multi->addTenant('bar', $this->getKmsProvider($multi->getBackend()));
        $multi->addTenant('baz', $this->getKmsProvider($multi->getBackend()));

        $ciphersweet = new CipherSweet($multi, $multi->getBackend());
        $encryptedRow = (new EncryptedRow($ciphersweet, 'users'))
            ->addTextField('username');

        $multi->setTenantColumnForTable('users', 'tenant_id');

        $multi->setActiveTenant('foo');
        $encrypted = $encryptedRow->encryptRow([
            'username' => 'alibaba',
            'password' => 'opensesame'
        ]);
        $this->assertSame($encrypted['tenant_id'], 'foo', 'Tenant ID is not being persisted');

        $wrong = $encrypted;
        $wrong['tenant_id'] = 'bar';
        try {
            $encryptedRow->decryptRow($wrong);
            $this->fail('Changing tenant ID must produce a decryption error');
        } catch (CipherSweetException|\SodiumException) {}
    }
}
