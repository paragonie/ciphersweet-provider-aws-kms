<?php
declare(strict_types=1);
namespace ParagonIE\CipherSweet\KeyProvider;

use Aws\Kms\KmsClient;
use ParagonIE\CipherSweet\Backend\BoringCrypto;
use ParagonIE\CipherSweet\Backend\Key\SymmetricKey;
use ParagonIE\CipherSweet\Contract\BackendInterface;
use ParagonIE\CipherSweet\Contract\StaticBlindIndexKeyProviderInterface;
use ParagonIE\CipherSweet\Exception\CipherSweetException;
use Psr\SimpleCache\CacheInterface;

class MultiTenantKmsKeyProvider extends MultiTenantProvider implements StaticBlindIndexKeyProviderInterface
{
    protected ?BackendInterface $backend = null;

    protected string|int|null $blindIndexTenant = null;

    /** @var array<string, string> $tenantColumnMap */
    protected array $tenantColumnMap = [];

    protected ?CacheInterface $cache = null;

    protected ?TenantEDKInterface $edkLookup = null;

    protected ?KmsClient $kmsClient = null;

    public function __construct(
        array $keyProviders,
        int|string|null $active = null,
        ?BackendInterface $backend = null,
        ?KmsClient $kmsClient = null,
        ?TenantEDKInterface $edkLookup = null,
        ?CacheInterface $cache = null,
    ) {
        if (is_null($backend)) {
            $backend = new BoringCrypto(); // Same default as CipherSweet
        }
        foreach ($keyProviders as $name => $keyProvider) {
            if (!($keyProvider instanceof KmsKeyProvider)) {
                throw new \TypeError('Key Provider is not a KMS key provider: ' . $name);
            }
            if ($keyProvider->getBackend() instanceof $backend) {
                throw new \TypeError('KeyProvider has the wrong backend:' . $name);
            }
        }
        parent::__construct($keyProviders, $active);
        $this->backend = $backend;
        $this->edkLookup = $edkLookup;
        $this->kmsClient = $kmsClient;
        $this->cache = $cache;
    }

    public function createTenant(
        string|int $index,
        string $keyID,
        array $encryptionContext = []
    ): KmsKeyProvider {
        $newProvider = KmsKeyProvider::generate(
            $this->kmsClient,
            $this->backend,
            $keyID,
            $encryptionContext,
            $this->cache
        );
        if (!is_null($this->edkLookup)) {
            return $this->edkLookup->createTenant($index, $newProvider);
        }
        return $newProvider;
    }

    /**
     * @return SymmetricKey
     * @throws CipherSweetException
     */
    public function getSymmetricKey(): SymmetricKey
    {
        if (\is_null($this->active)) {
            throw new CipherSweetException('Active tenant not set');
        }

        if (!array_key_exists($this->active, $this->tenants) && !is_null($this->edkLookup)) {
            $this->lookupEDKFor($this->active);
        }
        return $this->getActiveTenant()->getSymmetricKey();
    }

    public function getBackend(): BackendInterface|null
    {
        return $this->backend;
    }

    public function getTenantFromRow(array $row, string $tableName): string|int
    {
        if (!array_key_exists($tableName, $this->tenantColumnMap)) {
            throw new CipherSweetException('Column name not specified for table ' . $tableName);
        }
        $column = $this->tenantColumnMap[$tableName];
        if (!array_key_exists($column, $row)) {
            throw new CipherSweetException('Tenant information is not provided');
        }
        if (!is_string($row[$column]) && !is_int($row[$column])) {
            throw new CipherSweetException('Tenant information is the wrong type: ' . gettype($row[$column]));
        }
        return $row[$column];
    }

    /**
     * @throws CipherSweetException
     */
    public function injectTenantMetadata(array $row, string $tableName): array
    {
        if (is_null($this->active)) {
            return $row;
        }
        if (!array_key_exists($tableName, $this->tenantColumnMap)) {
            throw new CipherSweetException('Table ' . $tableName . ' does not have a column for tenant ID');
        }
        $column_name = $this->tenantColumnMap[$tableName];
        $row[$column_name] = $this->active;
        return $row;
    }

    /**
     * @param string|int $index
     * @return string
     * @throws CipherSweetException
     */
    public function lookupEDKFor(string|int $index): string
    {
        if (array_key_exists($index, $this->tenants)) {
            $tenant = $this->tenants[$index];
            if (!($tenant instanceof KmsKeyProvider)) {
                throw new \TypeError('Tenant type requirement somehow bypassed');
            }
            // Return the EDK since it's already loaded
            return $tenant->getEncryptedDataKey();
        }
        if (is_null($this->edkLookup)) {
            throw new CipherSweetException('EDK lookup callback not specified');
        }
        if (is_null($this->kmsClient)) {
            throw new CipherSweetException('KMS client not defined');
        }
        $response = $this->edkLookup->lookupTenantData($index);
        $this->addTenant($index, new KmsKeyProvider(
            $this->kmsClient,
            $this->backend,
            $response->keyId,
            $response->encryptionContext,
            $response->edk,
            $this->cache
        ));
        // Finally, return the EDK
        return $response->edk;
    }

    /**
     * @param array-key $index
     * @return static
     *
     * @throws CipherSweetException
     */
    public function setActiveTenant(string|int $index): static
    {
        if (!array_key_exists($index, $this->tenants) && !is_null($this->edkLookup)) {
            $this->lookupEDKFor($index);
        }
        $this->active = $index;
        return $this;
    }

    public function setDataKeyCache(CacheInterface $cache): static
    {
        $this->cache = $cache;
        return $this;
    }

    public function setEDKLookup(TenantEDKInterface $lookup): static
    {
        $this->edkLookup = $lookup;
        return $this;
    }

    public function setKmsClient(KmsClient $kmsClient): static
    {
        $this->kmsClient = $kmsClient;
        return $this;
    }

    public function setTenantColumnForTable(string $tableName, string $tenantColumnName): static
    {
        $this->tenantColumnMap[$tableName] = $tenantColumnName;
        return $this;
    }

    public function getStaticBlindIndexTenant(): string|int|null
    {
        return $this->blindIndexTenant;
    }

    public function setStaticBlindIndexTenant(int|string|null $tenant = null): void
    {
        $this->blindIndexTenant = $tenant;
    }
}
