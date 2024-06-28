# Cryptor Library

A simple PHP library for encrypting and decrypting data using AES-256-CBC.

## Installation

You can install the Cryptor library via Composer. Run the following command in your project directory:

```sh
composer require webnarmin/cryptor
```

## Usage

Here's a quick example of how to use the Cryptor class:

### Encrypting Data

```php
<?php

require 'vendor/autoload.php';

use webnarmin\Cryptor\Cryptor;

$privateKey = 'your_private_key';
$publicKey = 'your_public_key';
$data = 'Hello, world!';

$cryptor = new Cryptor($privateKey);
$encryptedData = $cryptor->encrypt($data, $publicKey);

echo 'Encrypted Data: ' . $encryptedData;
```

### Decrypting Data

```php
<?php

require 'vendor/autoload.php';

use webnarmin\Cryptor\Cryptor;

$privateKey = 'your_private_key';
$publicKey = 'your_public_key';
$encryptedData = 'your_encrypted_data';

$cryptor = new Cryptor($privateKey);
$decryptedData = $cryptor->decrypt($encryptedData, $publicKey);

echo 'Decrypted Data: ' . $decryptedData;
```

## Running Tests

To run tests, you need to have PHPUnit installed. If you don't have it installed, you can install it via Composer:

```sh
composer require --dev phpunit/phpunit
```

Run the tests using the following command:

```sh
vendor/bin/phpunit
```

## License

This library is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
