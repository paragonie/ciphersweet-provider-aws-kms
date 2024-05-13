<?php
declare(strict_types=1);
namespace ParagonIE\CipherSweet\KeyProvider\Tests;

use ParagonIE\CipherSweet\Exception\CipherSweetException;
use ParagonIE\CipherSweet\KeyProvider\KmsKeyProvider;
use ParagonIE\CipherSweet\KeyProvider\LookupResponse;
use ParagonIE\CipherSweet\KeyProvider\TenantEDKInterface;
use ParagonIE\EasyDB\EasyDB;
use ParagonIE\EasyDB\Factory;

class EasyDBLookup implements TenantEDKInterface
{
    public function __construct(private EasyDB $db)
    {}

    public static function initForTests(): self
    {
        return new EasyDBLookup(Factory::create('sqlite::memory:'));
    }

    public function createTenant(int|string $index, KmsKeyProvider $provider): KmsKeyProvider
    {
        if ($this->db->exists("SELECT count(*) FROM tenants WHERE tenant_id = ?", $index)) {
            // If it already exists, never clobber it!
            $realData = $this->lookupTenantData($index);
            return $provider
                ->withKeyID($realData->keyId)
                ->withEncryptionContext($realData->encryptionContext)
                ->withEncryptedDataKey($realData->edk);
        }
        $this->db->insert('tenants', [
            'edk' => $provider->getEncryptedDataKey(),
            'keyid' => $provider->getKeyId(),
            'enc_ctx' => json_encode($provider->getEncryptionContext())
        ]);
        return $provider;
    }

    public function lookupTenantData(int|string $index): LookupResponse
    {
        $row = $this->db->row("SELECT edk, keyid, enc_ctx FROM tenants WHERE tenant_id = ?", $index);
        if (empty($row)) {
            throw new CipherSweetException('No such tenant is defined');
        }
        return new LookupResponse(
            $row['edk'],
            $row['keyid'],
            json_decode($row['enc_ctx'] ?? '[]', true)
        );
    }
}
