<?php

declare(strict_types=1);

namespace webnarmin\Cryptor;

use JsonException;
use webnarmin\Cryptor\Exception\CryptorException;

class Cryptor
{
    private const CURRENT_PREFIX = 'cryptor:v2:';
    private const CURRENT_CIPHER_METHOD = 'aes-256-gcm';
    private const LEGACY_CIPHER_METHOD = 'aes-256-cbc';
    private const NONCE_LENGTH = 12;
    private const TAG_LENGTH = 16;

    private string $privateKey;

    public function __construct(string $privateKey)
    {
        $this->privateKey = $privateKey;
    }

    /**
     * Encrypt data using authenticated encryption.
     *
     * The returned payload is versioned. decrypt() still accepts legacy v1.0
     * AES-CBC payloads for backward compatibility.
     */
    public function encrypt(string $data, string $publicKey): string
    {
        $nonce = random_bytes(self::NONCE_LENGTH);
        $tag = '';
        $ciphertext = openssl_encrypt(
            $data,
            self::CURRENT_CIPHER_METHOD,
            $this->generateKey($publicKey, 'aead'),
            OPENSSL_RAW_DATA,
            $nonce,
            $tag,
            $this->associatedData($publicKey),
            self::TAG_LENGTH
        );

        if ($ciphertext === false || strlen($tag) !== self::TAG_LENGTH) {
            throw CryptorException::encryptionFailed($this->lastOpenSslError());
        }

        return self::CURRENT_PREFIX . $this->base64UrlEncode(json_encode([
            'alg' => 'A256GCM',
            'nonce' => $this->base64UrlEncode($nonce),
            'tag' => $this->base64UrlEncode($tag),
            'ciphertext' => $this->base64UrlEncode($ciphertext),
        ], JSON_THROW_ON_ERROR));
    }

    /**
     * Decrypt data while preserving the v1.0 failure contract.
     *
     * Use decryptOrFail() when failure must be explicit.
     */
    public function decrypt(string $data, string $publicKey): string
    {
        try {
            return $this->decryptOrFail($data, $publicKey);
        } catch (CryptorException $exception) {
            return '';
        }
    }

    /**
     * @throws CryptorException
     */
    public function decryptOrFail(string $data, string $publicKey): string
    {
        if (strpos($data, self::CURRENT_PREFIX) === 0) {
            return $this->decryptCurrentPayload($data, $publicKey);
        }

        return $this->decryptLegacyPayload($data, $publicKey);
    }

    /**
     * @throws CryptorException
     */
    private function decryptCurrentPayload(string $data, string $publicKey): string
    {
        $encodedPayload = substr($data, strlen(self::CURRENT_PREFIX));
        $payloadJson = $this->base64UrlDecode($encodedPayload);
        if ($payloadJson === null) {
            throw CryptorException::invalidPayload('Payload is not valid base64url.');
        }

        try {
            $payload = json_decode($payloadJson, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw CryptorException::invalidPayload('Payload is not valid JSON.', $exception);
        }

        if (!is_array($payload) || array_is_list($payload)) {
            throw CryptorException::invalidPayload('Payload must be a JSON object.');
        }

        if (($payload['alg'] ?? null) !== 'A256GCM') {
            throw CryptorException::invalidPayload('Unsupported payload algorithm.');
        }

        $nonce = $this->decodePayloadField($payload, 'nonce');
        $tag = $this->decodePayloadField($payload, 'tag');
        $ciphertext = $this->decodePayloadField($payload, 'ciphertext');

        if (strlen($nonce) !== self::NONCE_LENGTH) {
            throw CryptorException::invalidPayload('Payload nonce has invalid length.');
        }

        if (strlen($tag) !== self::TAG_LENGTH) {
            throw CryptorException::invalidPayload('Payload tag has invalid length.');
        }

        $plaintext = openssl_decrypt(
            $ciphertext,
            self::CURRENT_CIPHER_METHOD,
            $this->generateKey($publicKey, 'aead'),
            OPENSSL_RAW_DATA,
            $nonce,
            $tag,
            $this->associatedData($publicKey)
        );

        if ($plaintext === false) {
            throw CryptorException::decryptionFailed($this->lastOpenSslError());
        }

        return $plaintext;
    }

    /**
     * @throws CryptorException
     */
    private function decryptLegacyPayload(string $data, string $publicKey): string
    {
        $decoded = base64_decode($data, true);
        if ($decoded === false) {
            throw CryptorException::invalidPayload('Legacy payload is not valid base64.');
        }

        $parts = explode('::', $decoded, 2);
        if (count($parts) !== 2) {
            throw CryptorException::invalidPayload('Legacy payload has invalid structure.');
        }

        [$encryptedData, $iv] = $parts;
        $ivLength = openssl_cipher_iv_length(self::LEGACY_CIPHER_METHOD);
        if ($ivLength === false) {
            throw CryptorException::decryptionFailed('Unsupported legacy cipher.');
        }

        $plaintext = openssl_decrypt(
            $encryptedData,
            self::LEGACY_CIPHER_METHOD,
            $this->generateKey($publicKey, 'legacy'),
            0,
            str_pad($iv, $ivLength, "\0")
        );

        if ($plaintext === false) {
            throw CryptorException::decryptionFailed($this->lastOpenSslError());
        }

        return $plaintext;
    }

    /**
     * @param array<string, mixed> $payload
     *
     * @throws CryptorException
     */
    private function decodePayloadField(array $payload, string $field): string
    {
        $value = $payload[$field] ?? null;
        if (!is_string($value) || $value === '') {
            throw CryptorException::invalidPayload("Payload field '{$field}' must be a non-empty string.");
        }

        $decoded = $this->base64UrlDecode($value);
        if ($decoded === null) {
            throw CryptorException::invalidPayload("Payload field '{$field}' is not valid base64url.");
        }

        return $decoded;
    }

    private function generateKey(string $publicKey, string $context): string
    {
        if ($context === 'legacy') {
            return hash('sha256', $this->privateKey . $publicKey, true);
        }

        return hash_hkdf('sha256', $this->privateKey, 32, 'webnarmin/cryptor:' . $context, $publicKey);
    }

    private function associatedData(string $publicKey): string
    {
        return 'webnarmin/cryptor:' . hash('sha256', $publicKey);
    }

    private function base64UrlEncode(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }

    private function base64UrlDecode(string $value): ?string
    {
        $remainder = strlen($value) % 4;
        if ($remainder === 1) {
            return null;
        }

        if ($remainder > 0) {
            $value .= str_repeat('=', 4 - $remainder);
        }

        $decoded = base64_decode(strtr($value, '-_', '+/'), true);

        return $decoded === false ? null : $decoded;
    }

    private function lastOpenSslError(): ?string
    {
        $error = openssl_error_string();

        return $error === false ? null : $error;
    }
}
