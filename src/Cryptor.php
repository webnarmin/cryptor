<?php

namespace webnarmin\Cryptor;

class Cryptor
{
    private const CIPHER_METHOD = 'aes-256-cbc';

    private string $privateKey;

    public function __construct(string $privateKey)
    {
        $this->privateKey = $privateKey;
    }

    public function encrypt(string $data, string $publicKey): string
    {
        $key = $this->generateKey($publicKey);
        $ivLength = openssl_cipher_iv_length(self::CIPHER_METHOD);
        $iv = random_bytes($ivLength);

        $encrypted = openssl_encrypt($data, self::CIPHER_METHOD, $key, 0, $iv);
        if ($encrypted === false) {
            throw new \RuntimeException('Encryption failed: ' . openssl_error_string());
        }

        // Combine the IV and the encrypted data
        $combined = base64_encode($iv . $encrypted);
        return $combined;
    }

    public function decrypt(string $data, string $publicKey): string
    {
        $key = $this->generateKey($publicKey);
        $decodedData = base64_decode($data);
        if ($decodedData === false) {
            throw new \RuntimeException('Base64 decode failed');
        }

        $ivLength = openssl_cipher_iv_length(self::CIPHER_METHOD);
        $iv = substr($decodedData, 0, $ivLength);
        $encryptedData = substr($decodedData, $ivLength);

        $decrypted = openssl_decrypt($encryptedData, self::CIPHER_METHOD, $key, 0, $iv);
        if ($decrypted === false) {
            throw new \RuntimeException('Decryption failed: ' . openssl_error_string());
        }

        return $decrypted;
    }

    private function generateKey(string $publicKey): string
    {
        return hash('sha256', $this->privateKey . $publicKey, true);
    }
}
