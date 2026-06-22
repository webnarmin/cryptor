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
        $iv = random_bytes(openssl_cipher_iv_length(self::CIPHER_METHOD));
        $encrypted = openssl_encrypt($data, self::CIPHER_METHOD, $key, 0, $iv);
        return base64_encode($encrypted . '::' . $iv);
    }

    public function decrypt(string $data, string $publicKey): string
    {
        $key = $this->generateKey($publicKey);
        [$encryptedData, $iv] = explode('::', base64_decode($data), 2);
        $iv = str_pad($iv, openssl_cipher_iv_length(self::CIPHER_METHOD), "\0"); // Ensure IV is 16 bytes long
        return openssl_decrypt($encryptedData, self::CIPHER_METHOD, $key, 0, $iv) ?: '';
    }

    private function generateKey(string $publicKey): string
    {
        return hash('sha256', $this->privateKey . $publicKey, true);
    }
}
