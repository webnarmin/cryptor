# Cryptor

`webnarmin/cryptor` is a small PHP encryption helper.

Version `2.x` writes authenticated, versioned AES-256-GCM payloads and keeps read support for legacy `1.x` AES-256-CBC payloads to make migrations possible.

## Installation

```sh
composer require webnarmin/cryptor
```

## Version Contract

- `1.x` wrote legacy AES-256-CBC payloads.
- `2.x` writes `cryptor:v2:` AES-256-GCM payloads.
- `2.x` can decrypt legacy `1.x` payloads.
- `2.x` is a major version because encrypted output format changes.

## Security Model

`Cryptor` is a symmetric encryption helper. The `$privateKey` and `$publicKey` names are kept from the `1.x` API, but this library does not implement public-key encryption. Both values are used as key material for deriving the encryption key.

## Usage

```php
<?php

require 'vendor/autoload.php';

use webnarmin\Cryptor\Cryptor;

$privateKey = 'your_private_key';
$publicKey = 'your_public_key';
$data = 'Hello, world!';

$cryptor = new Cryptor($privateKey);
$encryptedData = $cryptor->encrypt($data, $publicKey);
$decryptedData = $cryptor->decrypt($encryptedData, $publicKey);
```

`decrypt()` preserves the `1.x` soft-failure behavior and returns an empty string when decryption fails.

For strict failure handling, use `decryptOrFail()`:

```php
try {
    $decryptedData = $cryptor->decryptOrFail($encryptedData, $publicKey);
} catch (\webnarmin\Cryptor\Exception\CryptorException $exception) {
    // Invalid payload, wrong key, tampered ciphertext, or OpenSSL failure.
}
```

## Running Tests

```sh
composer check
```

## License

This library is licensed under the MIT License.
