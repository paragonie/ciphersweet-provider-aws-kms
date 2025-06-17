# AWS KMS KeyProvider for CipherSweet (PHP)

[![Static Analysis](https://github.com/paragonie/ciphersweet-provider-aws-kms/actions/workflows/psalm.yml/badge.svg)](https://github.com/paragonie/ciphersweet-provider-aws-kms/actions)
[![Latest Stable Version](https://poser.pugx.org/paragonie/ciphersweet-provider-aws-kms/v/stable)](https://packagist.org/packages/paragonie/ciphersweet-provider-aws-kms)
[![Latest Unstable Version](https://poser.pugx.org/paragonie/ciphersweet-provider-aws-kms/v/unstable)](https://packagist.org/packages/paragonie/ciphersweet-provider-aws-kms)
[![License](https://poser.pugx.org/paragonie/ciphersweet-provider-aws-kms/license)](https://packagist.org/packages/paragonie/ciphersweet-provider-aws-kms)
[![Downloads](https://img.shields.io/packagist/dt/paragonie/ciphersweet-provider-aws-kms.svg)](https://packagist.org/packages/paragonie/ciphersweet-provider-aws-kms)

This repository exists to provide a distinct Composer package useful for 
integrating [CipherSweet](https://github.com/paragonie/ciphersweet) with AWS KMS.

## Installing

```terminal
composer require paragonie/ciphersweet-provider-aws-kms
```

## Usage

### KmsKeyProvider

The basic `KmsKeyProvider` class is intended to work with a single Encrypted Data Key (EDK).
If you're looking to provide multi-tenancy (e.g., one data key per user), look instead at
[MultiTenantKmsKeyProvider](#multitenantkmskeyprovider).

First, you'll need a [`KmsClient`](https://docs.aws.amazon.com/aws-sdk-php/v3/api/class-Aws.Kms.KmsClient.html)
object, a desired [CipherSweet backend](https://ciphersweet.paragonie.com/php/setup#select-your-backend), and
the Key ID or ARN for the KMS key you want to use. 

```php
<?php
use Aws\Kms\KmsClient;
use ParagonIE\Certainty\RemoteFetch;
use ParagonIE\CipherSweet\Backend\BoringCrypto;
use ParagonIE\CipherSweet\KeyProvider\KmsKeyProvider;

// Recommended: always use the latest CACert bundle
$remoteFetch = new RemoteFetch('/path/to/cacert-dir');
$latestBundle = $remoteFetch->getLatestBundle()->getFilePath();
$keyID = ''; /* get this from KMS */

$kmsClient = new KmsClient([
    'profile' => 'default',
    'region' => 'us-east-1',
    'http' => ['verify' => $latestBundle]
]);

// Recommended: Use encryption context for your apps
$encryptionContext = [
    'app' => 'foo.example.com'
];
```

Once you have these value defined, you will first want to generate a new data key and persist
the Encrypted Data Key to be reused, like so:

```php
$newKey = KmsKeyProvider::generate(
    $kmsClient,
    new BoringCrypto(), // Your backend goes here
    $keyID,
    $encryptionContext
);
// Save this somewhere so you can reuse it:
$edk = $newKey->getEncryptedDataKey();
```

From now on, you can simply load your backend as follows:

```php
// Moving forward, you can simply instantiate your key provider like so:
$provider = new KmsKeyProvider(
    $kmsClient,
    new BoringCrypto(), // Your backend goes here
    $keyID,
    $encryptionContext,
    $edk
);
```

See also: [caching](#caching)

### MultiTenantKmsKeyProvider

The purpose of the provided `MultiTenantKmsKeyProvider` class is to facilitate workloads where
multiple users have their data encrypted with different EDKs. This can safely be used with the
same KMS Key or with different KMS Keys. Whatever makes the most sense for your application.

The basic idea behind our design is that some metadata about tenants is stored in a column
(which has a value populated for each row):

```php
/** @var \ParagonIE\CipherSweet\KeyProvider\MultiTenantKmsKeyProvider $multiPro */
$multiPro->setTenantColumnForTable('table_name', 'tenant_id_column_name');
```

Somewhere else in your application, you will need a mapping of tenant IDs to EDKs.
This **MAY** be a separate SQL table. We have provided some convenience utilities to make
integration easier, but you're free to decide your own mapping and persistence strategy.

To that end, our multi-tenant key provider allows you to provide a class that implements 
`TenantEDKInterface` to fetch EDKs and other metadata, as well as create tenants. You are
free to implement this however you wish.  **See, for example, [our EasyDB test class](tests/EasyDBLookup.php).**

To create a new tenant (and a new EDK), simply pass the new tenant's ID, the KMS Key ID or ARN,
and Encryption Context to use for encrypting this key.

```php
// Calling createTenant() will persist it to memory
$specificProvider = $multiPro->createTenant($tenantID, $kmsKeyID, $encryptionContext);
```

With this little bit of additional glue code on your end, you're all set.

```php
<?php
use ParagonIE\CipherSweet\CipherSweet;
use ParagonIE\CipherSweet\EncryptedMultiRows;
use ParagonIE\CipherSweet\KeyProvider\MultiTenantKmsKeyProvider;

/**
 * @var \Aws\Kms\KmsClient $kmsClient
 * @var \ParagonIE\CipherSweet\KeyProvider\TenantEDKInterface $edkLookup
 */

$multiPro = (new MultiTenantKmsKeyProvider())
    ->setEDKLookup($edkLookup)
    ->setKmsClient($kmsClient);

$multiPro->setTenantColumnForTable('table_1_name', 'tenant_id');

$multiPro->createTenant('example_1', 'kms_key_id_goes_here', ['region' => 'us-east-2']);
$multiPro->createTenant('example_2', 'kms_key_id_goes_here', ['region' => 'us-west-1']);

$engine = new CipherSweet($multiPro, $multiPro->getBackend());
$encryptManyRows = (new EncryptedMultiRows($engine))->setAutoBindContext(true);
```

And then you can [just use CipherSweet as usual](https://ciphersweet.paragonie.com/php/usage).

#### Using a Static Key for Blind Indexing with Multi-Tenancy

You can toggle this on with a single call to multi-tenant key provider.

```php
$multiPro->setStaticBlindIndexTenant("dedicated-searching-tenant-id-goes-here");
```

To toggle this feature back off, pass `null` instead:

```php
$multiPro->setStaticBlindIndexTenant(null);
```

### Caching

Network round-trips to AWS KMS can be a performance bottleneck for your application, especially
if you're running it outside of AWS.

Applications **MAY** provide a PSR-16 compatible cache to persist plaintext data keys across
requests.

```php
/**
 * @var \ParagonIE\CipherSweet\KeyProvider\MultiTenantKmsKeyProvider $multiPro
 * @var \ParagonIE\CipherSweet\KeyProvider\KmsKeyProvider $provider
 * @var \Psr\SimpleCache\CacheInterface $yourCache
 */

// This will pass $yourCache to all KmsKeyProviders managed by this multi-tenant provider:
$multiPro->setDataKeyCache($yourCache);

// For only one single-tenant provider:
$provider->setDataKeyCache($yourCache);
```
