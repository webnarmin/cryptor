<?php

use PHPUnit\Framework\TestCase;
use webnarmin\Cryptor\Cryptor;

class CryptorTest extends TestCase
{
    private string $privateKey = 'test_private_key';
    private string $publicKey = 'test_public_key';
    private Cryptor $cryptor;

    protected function setUp(): void
    {
        $this->cryptor = new Cryptor($this->privateKey);
    }

    public function testEncryptAndDecrypt(): void
    {
        $data = 'Hello, world!';
        $encryptedData = $this->cryptor->encrypt($data, $this->publicKey);
        $this->assertNotEquals($data, $encryptedData, 'Data should be encrypted.');

        $decryptedData = $this->cryptor->decrypt($encryptedData, $this->publicKey);
        $this->assertEquals($data, $decryptedData, 'Decrypted data should match the original data.');
    }

    public function testDecryptWithWrongPrivateKey(): void
    {
        $data = 'Hello, world!';
        $encryptedData = $this->cryptor->encrypt($data, $this->publicKey);

        $wrongCryptor = new Cryptor('wrong_private_key');
        $decryptedData = $wrongCryptor->decrypt($encryptedData, $this->publicKey);
        $this->assertNotEquals($data, $decryptedData, 'Decrypted data with wrong private key should not match the original data.');
    }

    public function testDecryptWithWrongPublicKey(): void
    {
        $data = 'Hello, world!';
        $encryptedData = $this->cryptor->encrypt($data, $this->publicKey);

        $decryptedData = $this->cryptor->decrypt($encryptedData, 'wrong_public_key');
        $this->assertNotEquals($data, $decryptedData, 'Decrypted data with wrong public key should not match the original data.');
    }
}
