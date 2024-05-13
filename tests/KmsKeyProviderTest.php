<?php
declare(strict_types=1);
namespace ParagonIE\CipherSweet\KeyProvider\Tests;

use Aws\Kms\KmsClient;
use ParagonIE\Certainty\RemoteFetch;
use ParagonIE\CipherSweet\Backend\BoringCrypto;
use ParagonIE\CipherSweet\Backend\FIPSCrypto;
use ParagonIE\CipherSweet\Backend\Key\SymmetricKey;
use ParagonIE\CipherSweet\Contract\BackendInterface;
use ParagonIE\CipherSweet\KeyProvider\KmsKeyProvider;
use ParagonIE\ConstantTime\Hex;
use PHPUnit\Framework\TestCase;

/**
 * @covers KmsKeyProvider
 */
class KmsKeyProviderTest extends TestCase
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
        return new KmsKeyProvider(
            $kmsClient,
            $backend,
            $config['key-arn']
        );
    }

    public function keyProvider(): array
    {
        return [
            [$this->getKmsProvider(new BoringCrypto)],
            [$this->getKmsProvider(new FIPSCrypto)],
        ];
    }

    /**
     * @dataProvider keyProvider
     */
    public function testEncryptDecrypt(KmsKeyProvider $provider): void
    {
        $symmetric = new SymmetricKey(random_bytes(32));
        $wrapped = $provider->encryptDataKey($symmetric);
        $unwrapped = $provider->withEncryptedDataKey($wrapped)->getSymmetricKey();
        $this->assertSame(
            Hex::encode($unwrapped->getRawKey()),
            Hex::encode($symmetric->getRawKey()),
        );
    }
}
