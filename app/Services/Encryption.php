<?php

declare(strict_types=1);

namespace App\Services;

use GuzzleHttp\Psr7\Stream;
use Psr\Http\Message\StreamInterface;

readonly class Encryption
{
    private const /*string*/ HASH_ALGORITHM = 'sha256';

    private const /*string*/ CIPHER_ALGORITHM = 'aes-256-cbc';

    public function encryptFile(string $filePath): string
    {
        if (! file_exists($filePath)) {
            throw new CryptException('File does not exist');
        }
        $stream = fopen($filePath, 'r');
        fseek($stream, 0);
        $stream = new Stream($stream);
        $mediaType = $this->getMediaType($filePath);
        $encryptedStream = $this->encryptStreamData($stream, $mediaType);

        return $encryptedStream;
    }

    public function decryptFile(string $filePath): string
    {
        if (! file_exists($filePath)) {
            throw new CryptException('File does not exist');
        }

        $stream = fopen($filePath, 'r');
        fseek($stream, 0);
        $stream = new Stream($stream);
        $mediaType = $this->getMediaType($filePath);

        // Decrypt the stream data one by one
        $decryptedStream = $this->decryptStreamData($stream, $mediaType);

        return $decryptedStream;
    }

    private function getMediaType(string $filePath): MediaTypeEnum
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

    private function generateMediaKey($keyFileName): string
    {
        // Generate a mediaKey (32 bytes)
        $mediaKey = random_bytes(32);
        file_put_contents($keyFileName, $mediaKey);

        return $mediaKey;
    }

    private function getMediaKeyFromFile($keyFileName): string
    {
        if (! file_exists($keyFileName)) {
            throw new CryptException('mediaKey not found');
        }
        // Obtain mediaKey (your implementation to obtain the media key)
        $mediaKey = file_get_contents($keyFileName);

        if (empty($mediaKey)) {
            throw new CryptException('mediaKey is empty');
        }

        return $mediaKey;
    }

    public function encryptStreamData(StreamInterface $stream, MediaTypeEnum $mediaType, $keyFileName = 'mediaKey.txt'): string
    {
        //1.1 use existing mediaKey
        try {
            $mediaKey = $this->getMediaKeyFromFile($keyFileName);
        } catch (CryptException) {
            //1.2 or generate new one
            $mediaKey = $this->generateMediaKey($keyFileName);
        }
        //2. Expand it
        $mediaKeyExpanded = $this->getExpandedMediaKey($mediaKey, $mediaType);

        //3. Split `mediaKeyExpanded`
        [$iv, $cipherKey, $macKey] = $this->splitExpandedKey($mediaKeyExpanded);

        //4. Encrypt the file
        $enc = $this->encrypt($stream, $cipherKey, $iv);

        //5. Sign `iv + enc` with `macKey`
        $mac = $this->getMac($iv, $enc, $macKey);

        //6. Append `mac` to the `enc`
        $encryptedStream = $enc.$mac;

        return $encryptedStream;
    }

    private function encrypt(StreamInterface $stream, string $cipherKey, string $iv): string
    {
        // Initialize the encryption buffer
        $encryptedData = '';

        // Encrypt the stream data chunk by chunk
        while (! $stream->eof()) {
            // Read a chunk of data from the stream
            $chunk = $stream->read(1024);

            // Encrypt the chunk of data
            $encryptedChunk = openssl_encrypt(
                $chunk,
                self::CIPHER_ALGORITHM,
                $cipherKey,
                OPENSSL_RAW_DATA,
                $iv
            );

            if ($encryptedChunk === false) {
                throw new CryptException('Failed to encrypt data: ' . openssl_error_string());
            }
            // Append the encrypted chunk to the encrypted data
            $encryptedData .= $encryptedChunk;
        }

        return $encryptedData;
    }

    private function validateMediaData(string $encryptedFile, string $mac, string $iv, string $macKey): void
    {
        // Validate media data with HMAC by signing iv + encryptedFile with macKey using SHA-256
        $computedMac = $this->getMac($iv, $encryptedFile, $macKey);

        // Compare the computed MAC with the received MAC
        if (! hash_equals($mac, $computedMac)) {
            throw new CryptException('MAC validation failed');
        }
    }

    private function getFileAndMacFromEncryptedMedia(StreamInterface $stream): array
    {
        // Get the current position of the stream
        $currentPosition = $stream->tell();

        // Read the stream and split the encrypted media data and MAC
        $mediaData = (string) $stream;

        // Calculate the length of the MAC (10 bytes)
        $macLength = 10;

        // Extract the encrypted file data
        $encryptedFile = substr($mediaData, 0, -$macLength);

        // Extract the MAC from the end of the encrypted data
        $mac = substr($mediaData, -$macLength);

        // Rewind the stream to its original position
        $stream->seek($currentPosition);

        return [$encryptedFile, $mac];
    }

    public function decryptStreamData(StreamInterface $stream, MediaTypeEnum $mediaType, string $keyFileName = 'mediaKey.txt'): string
    {
        //1. Obtain `mediaKey`.
        $mediaKey = $this->getMediaKeyFromFile($keyFileName);

        //2. Expand it
        $mediaKeyExpanded = $this->getExpandedMediaKey($mediaKey, $mediaType);

        //3. Split `mediaKeyExpanded`
        [$iv, $cipherKey, $macKey] = $this->splitExpandedKey($mediaKeyExpanded);

        //4. Obtain file and mac
        [$file, $mac] = $this->getFileAndMacFromEncryptedMedia($stream);

        //5. Validate media data
        $this->validateMediaData($file, $mac, $iv, $macKey);

        //6. Decrypt `file`
        $decryptedFile = $this->decrypt($file, $cipherKey, $iv);

        return $decryptedFile;
    }

    private function decrypt(string $file, string $cipherKey, string $iv): string
    {
        // Initialize the decryption buffer
        $decryptedData = '';


        $decryptedData = openssl_decrypt(
            $file,
            self::CIPHER_ALGORITHM,
            $cipherKey,
            OPENSSL_RAW_DATA,
            $iv
        );

        // Decrypt the stream data chunk by chunk
//        while (! $stream->eof()) {
//
//            // Read a chunk of data from the stream
//            $chunk = $stream->read(1024);
//
//            // Decrypt the chunk of data
//            $decryptedChunk = openssl_decrypt(
//                $chunk,
//                self::CIPHER_ALGORITHM,
//                $cipherKey,
//                OPENSSL_RAW_DATA,
//                $iv
//            );
//
//            if ($decryptedChunk === false) {
//                throw new CryptException('Decrypted data failed: ' . openssl_error_string());
//            }
//            // Append the decrypted chunk to the decrypted data
//            $decryptedData .= $decryptedChunk;
//        }

        // Unpad the decrypted file
        return $this->unpad($decryptedData);
    }

    private function splitExpandedKey(string $mediaKeyExpanded): array
    {
        // Split the expanded key into iv, cipherKey, macKey, and refKey
        $iv = substr($mediaKeyExpanded, 0, 16);
        $cipherKey = substr($mediaKeyExpanded, 16, 32);
        $macKey = substr($mediaKeyExpanded, 48, 32);

        return [$iv, $cipherKey, $macKey];
    }

    private function unpad($data): string
    {
        $padding = ord($data[strlen($data) - 1]);

        return substr($data, 0, -$padding);
    }

    private function getExpandedMediaKey(string $mediaKey, MediaTypeEnum $mediaType): string
    {
        // Expand mediaKey to 112 bytes using HKDF with SHA-256 and type-specific application info
        return hash_hkdf(
            self::HASH_ALGORITHM,
            $mediaKey,
            112,
            $mediaType->value,
        );
    }

    private function getMac(string $iv, string $encryptedData, string $macKey): string
    {
        // Calculate HMAC for iv + encrypted data using macKey
        $mac = hash_hmac(
            self::HASH_ALGORITHM,
            $iv.$encryptedData,
            $macKey,
            true
        );

        // Take the first 10 bytes of the HMAC as the MAC
        return substr($mac, 0, 10);
    }
}
