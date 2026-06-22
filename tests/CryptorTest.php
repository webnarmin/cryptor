<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use webnarmin\Cryptor\Cryptor;
use webnarmin\Cryptor\Exception\CryptorException;

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
        $this->assertStringStartsWith('cryptor:v2:', $encryptedData);

        $decryptedData = $this->cryptor->decrypt($encryptedData, $this->publicKey);
        $this->assertEquals($data, $decryptedData, 'Decrypted data should match the original data.');
    }

    public function testEncryptUsesRandomNonce(): void
    {
        $data = 'Hello, world!';

        $this->assertNotSame(
            $this->cryptor->encrypt($data, $this->publicKey),
            $this->cryptor->encrypt($data, $this->publicKey)
        );
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

    public function testDecryptOrFailThrowsOnAuthenticationFailure(): void
    {
        $encryptedData = $this->cryptor->encrypt('Hello, world!', $this->publicKey);

        $this->expectException(CryptorException::class);

        (new Cryptor('wrong_private_key'))->decryptOrFail($encryptedData, $this->publicKey);
    }

    public function testTamperedPayloadFailsAuthentication(): void
    {
        $encryptedData = $this->cryptor->encrypt('Hello, world!', $this->publicKey);
        $tampered = substr($encryptedData, 0, -1) . (substr($encryptedData, -1) === 'A' ? 'B' : 'A');

        $this->assertSame('', $this->cryptor->decrypt($tampered, $this->publicKey));
    }

    public function testLegacyPayloadStillDecrypts(): void
    {
        $data = 'legacy payload';
        $legacyPayload = $this->legacyEncrypt($data, $this->privateKey, $this->publicKey);

        $this->assertSame($data, $this->cryptor->decrypt($legacyPayload, $this->publicKey));
        $this->assertSame($data, $this->cryptor->decryptOrFail($legacyPayload, $this->publicKey));
    }

    public function testMalformedPayloadReturnsEmptyStringAndStrictApiThrows(): void
    {
        $this->assertSame('', $this->cryptor->decrypt('not-a-valid-payload', $this->publicKey));

        $this->expectException(CryptorException::class);

        $this->cryptor->decryptOrFail('not-a-valid-payload', $this->publicKey);
    }

    private function legacyEncrypt(string $data, string $privateKey, string $publicKey): string
    {
        $iv = random_bytes(openssl_cipher_iv_length('aes-256-cbc'));
        $encrypted = openssl_encrypt(
            $data,
            'aes-256-cbc',
            hash('sha256', $privateKey . $publicKey, true),
            0,
            $iv
        );

        $this->assertIsString($encrypted);

        return base64_encode($encrypted . '::' . $iv);
    }
}
