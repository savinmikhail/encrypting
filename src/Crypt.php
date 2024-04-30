<?php

namespace Mikhail\Encryptor;

use Psr\Http\Message\StreamInterface;
use Mikhail\Encryptor\Enums\MediaTypeEnum;
use Mikhail\Encryptor\Exceptions\CorruptedMediaKeyException;
use Mikhail\Encryptor\Exceptions\EmptyFileException;
use Mikhail\Encryptor\Exceptions\FileNotFoundException;


abstract class Crypt
{
    protected const /*string*/ HASH_ALGORITHM = 'sha256';

    protected const /*string*/ CIPHER_ALGORITHM = 'aes-256-cbc';

    protected const /*int*/ MEDIA_KEY_LENGTH = 32;

    protected const /*int*/ MEDIA_KEY_EXPANDED_LENGTH = 112;

    protected const /*string*/ DEFAULT_MEDIA_KEY_FILE_NAME = 'mediaKey.txt';

    protected const /*int*/ MAC_LENGTH = 10;

    protected const /*int*/ BLOCK_SIZE = 16; // AES block size is 16 bytes (128 bits)

    protected MediaTypeEnum $mediaType;

    protected StreamInterface $stream;

    protected string $macKey;

    protected string $iv;

    protected function getCurrentIv(): string
    {
        return $this->iv;
    }

    protected function updateIv(string $cipherTextBlock): void
    {
        $this->iv = substr($cipherTextBlock, self::BLOCK_SIZE * -1);
    }

    protected function splitExpandedKey(string $mediaKeyExpanded): array
    {
        // Split the expanded key into iv, cipherKey, macKey, and refKey
        $iv = substr($mediaKeyExpanded, 0, 16);
        $cipherKey = substr($mediaKeyExpanded, 16, 32);
        $macKey = substr($mediaKeyExpanded, 48, 32);

        return [$iv, $cipherKey, $macKey];
    }

    protected function getExpandedMediaKey(): string
    {
        // Expand mediaKey to 112 bytes using HKDF with SHA-256 and type-specific application info
        return hash_hkdf(
            self::HASH_ALGORITHM,
            $this->mediaKey,
            self::MEDIA_KEY_EXPANDED_LENGTH,
            $this->mediaType->value,
        );
    }

    protected function getMac(string $iv, string $encryptedData, string $macKey): string
    {
        // Take the first 10 bytes of the HMAC as the MAC
        return substr(
            $this->calculateHmac($iv, $encryptedData, $macKey),
            0,
            self::MAC_LENGTH,
        );
    }

    protected function calculateHmac(string $iv, string $encryptedData, string $macKey): string
    {
        // Calculate HMAC for iv + encrypted data using macKey
        return hash_hmac(
            self::HASH_ALGORITHM,
            $iv.$encryptedData,
            $macKey,
            true
        );
    }
}
