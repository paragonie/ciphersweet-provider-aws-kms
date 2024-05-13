<?php
declare(strict_types=1);
namespace ParagonIE\CipherSweet\KeyProvider;

use Aws\Kms\KmsClient;
use ParagonIE\CipherSweet\Backend\Key\SymmetricKey;
use ParagonIE\CipherSweet\Contract\BackendInterface;
use ParagonIE\CipherSweet\Contract\KeyProviderInterface;
use ParagonIE\CipherSweet\Exception\CipherSweetException;
use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\ConstantTime\Binary;
use Psr\SimpleCache\CacheInterface;
use Psr\SimpleCache\InvalidArgumentException;

class KmsKeyProvider implements KeyProviderInterface
{
    public function __construct(
        protected KmsClient $kmsClient,
        protected BackendInterface $backend,
        protected string $keyId,
        protected array $encryptionContext = [],
        protected string $edk = '',
        protected ?CacheInterface $cache = null,
    ) {}

    public static function generate(
        KmsClient $kmsClient,
        BackendInterface $backend,
        string $keyId,
        array $encryptionContext = [],
        ?CacheInterface $cache = null,
    ): self {
        $prefix = $backend->getPrefix();
        $response = $kmsClient->generateDataKey([
            'KeyId' => $keyId,
            'NumberOfBytes' => 32,
            'EncryptionContext' =>
                ['CipherSweetHeader' => $prefix] + $encryptionContext
        ]);

        return new self(
            $kmsClient,
            $backend,
            $keyId,
            $encryptionContext,
            $backend->getPrefix() . Base64UrlSafe::encodeUnpadded($response['CiphertextBlob']),
            $cache
        );
    }

    public function encryptDataKey(SymmetricKey $key): string
    {
        $prefix = $this->backend->getPrefix();
        $response = $this->kmsClient->encrypt([
            'KeyId' => $this->keyId,
            'Plaintext' => $key->getRawKey(),
            'EncryptionContext' =>
                ['CipherSweetHeader' => $prefix] + $this->encryptionContext
        ]);
        return $prefix . Base64UrlSafe::encodeUnpadded($response['CiphertextBlob']);
    }

    public function getBackend(): BackendInterface
    {
        return $this->backend;
    }

    public function getEncryptedDataKey(): string
    {
        return $this->edk;
    }

    public function getEncryptionContext(): array
    {
        return $this->encryptionContext;
    }

    public function getKeyId(): string
    {
        return $this->keyId;
    }

    public function getKmsClient(): KmsClient
    {
        return $this->kmsClient;
    }

    /**
     * @throws CipherSweetException
     * @throws InvalidArgumentException
     */
    public function getSymmetricKey(): SymmetricKey
    {
        if (empty($this->edk)) {
            throw new CipherSweetException('EDK not set on this AWS KMS KeyProvider');
        }
        $prefix = $this->backend->getPrefix();
        if (!str_starts_with($this->edk, $prefix)) {
            throw new CipherSweetException('EDK is intended for the wrong backend');
        }

        if (!is_null($this->cache)) {
            if ($this->cache->has($this->edk)) {
                return $this->cache->get($this->edk);
            }
        }

        $edk = Binary::safeSubstr($this->edk,  Binary::safeStrlen($prefix));
        $response = $this->kmsClient->decrypt([
            'KeyId' => $this->keyId,
            'CiphertextBlob' => Base64UrlSafe::decodeNoPadding($edk),
            'EncryptionContext' =>
                ['CipherSweetHeader' => $this->backend->getPrefix()] + $this->encryptionContext
        ]);
        if (!is_null($this->cache)) {
            $this->cache->set($this->edk, new SymmetricKey($response['Plaintext']));
        }
        return new SymmetricKey($response['Plaintext']);
    }

    public function withDataKeyCache(CacheInterface $cache): self
    {
        $self = clone $this;
        $self->cache = $cache;
        return $self;
    }

    /**
     * @throws CipherSweetException
     */
    public function withEncryptedDataKey(string $edk): self
    {
        if (!str_starts_with($edk, $this->backend->getPrefix())) {
            throw new CipherSweetException('EDK is intended for the wrong backend');
        }
        $self = clone $this;
        $self->edk = $edk;
        return $self;
    }

    public function withEncryptionContext(array $ec): self
    {
        $self = clone $this;
        $self->encryptionContext = $ec;
        return $self;
    }

    public function withKeyID(string $keyId): self
    {
        $self = clone $this;
        $self->keyId = $keyId;
        return $self;
    }
}
