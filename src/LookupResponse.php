<?php
declare(strict_types=1);
namespace ParagonIE\CipherSweet\KeyProvider;

final class LookupResponse
{
    public function __construct(
        public readonly string $edk,
        public readonly string $keyId,
        public readonly array $encryptionContext = []
    ) {}
}
