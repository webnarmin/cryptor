<?php

declare(strict_types=1);

namespace webnarmin\Cryptor\Exception;

use RuntimeException;
use Throwable;

class CryptorException extends RuntimeException
{
    public static function encryptionFailed(?string $reason = null): self
    {
        return new self(self::withReason('Encryption failed.', $reason));
    }

    public static function decryptionFailed(?string $reason = null): self
    {
        return new self(self::withReason('Decryption failed.', $reason));
    }

    public static function invalidPayload(string $message, ?Throwable $previous = null): self
    {
        return new self($message, 0, $previous);
    }

    private static function withReason(string $message, ?string $reason): string
    {
        return $reason === null || $reason === '' ? $message : $message . ' ' . $reason;
    }
}
