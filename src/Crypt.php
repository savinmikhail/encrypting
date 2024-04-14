<?php

namespace Mikhail\Encryptor;
require 'vendor/autoload.php';
require __DIR__ . '/../src/Enums/MediaTypeEnum.php';

use GuzzleHttp\Psr7\Stream;
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

    protected string $iv;

    /**
     * @throws EmptyFileException
     * @throws FileNotFoundException
     */
    protected function getStreamFromFile(string $filePath): StreamInterface
    {
        if (! file_exists($filePath)) {
            throw new FileNotFoundException("File $filePath does not exist");
        }
        // Check if the file is empty
        if (filesize($filePath) === 0) {
            throw new EmptyFileException("File $filePath is empty");
        }
        $stream = fopen($filePath, 'r');
        fseek($stream, 0);

        return new Stream($stream);
    }

    protected function getMediaType(string $filePath): MediaTypeEnum
    {
        $ext = pathinfo($filePath, PATHINFO_EXTENSION);

        return match ($ext) {
            'jpg', 'jpeg', 'png', 'gif' => MediaTypeEnum::IMAGE,
            'txt', 'pdf', 'docx' => MediaTypeEnum::DOCUMENT,
            'mp4' => MediaTypeEnum::VIDEO,
            'mp3' => MediaTypeEnum::AUDIO,
            default => MediaTypeEnum::DOCUMENT,
        };
    }

    /**
     * @throws CorruptedMediaKeyException
     * @throws FileNotFoundException
     */
    protected function getMediaKeyFromFile(string $keyFileName): string
    {
        if (! file_exists($keyFileName)) {
            throw new FileNotFoundException('mediaKey not found');
        }

        // Obtain mediaKey (your implementation to obtain the media key)
        $mediaKey = file_get_contents($keyFileName);

        if (strlen($mediaKey) !== self::MEDIA_KEY_LENGTH) {
            throw new CorruptedMediaKeyException('mediaKey is not '.self::MEDIA_KEY_LENGTH.' bytes');
        }

        return $mediaKey;
    }

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

    protected function getExpandedMediaKey(string $mediaKey): string
    {
        // Expand mediaKey to 112 bytes using HKDF with SHA-256 and type-specific application info
        return hash_hkdf(
            self::HASH_ALGORITHM,
            $mediaKey,
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
