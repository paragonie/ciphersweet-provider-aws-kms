<?php
declare(strict_types=1);
namespace ParagonIE\CipherSweet\KeyProvider;

interface TenantEDKInterface
{
    public function createTenant(string|int $index, KmsKeyProvider $provider): KmsKeyProvider;

    public function lookupTenantData(string|int $index): LookupResponse;
}
