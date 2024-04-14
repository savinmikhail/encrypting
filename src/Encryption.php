<?php

declare(strict_types=1);

namespace Mikhail\Encryptor;
require 'vendor/autoload.php';
require_once __DIR__ . '/../src/Crypt.php';

use Random\RandomException;
use Mikhail\Encryptor\Enums\MediaTypeEnum;
use Mikhail\Encryptor\Exceptions\CorruptedMediaKeyException;
use Mikhail\Encryptor\Exceptions\CryptException;
use Mikhail\Encryptor\Exceptions\FileNotFoundException;

class Encryption extends Crypt
{
    protected string $macKey;

    /**
     * принимает файл, возвращает строоку зашифрованных байтов
     */
    public function encryptFile(
        string $filePath,
        /** здесь ключ опционален, если не предоставлен, то сгенерим сами */
        ?string $keyFileName = null,
    ): string {
        $stream = $this->getStreamFromFile($filePath);
        $this->stream = $stream;

        $mediaType = $this->getMediaType($filePath);
        $this->mediaType = $mediaType;

        return $this->encryptStreamData($mediaType, $keyFileName);
    }

    /**
     * @throws RandomException
     */
    protected function generateMediaKey(): string
    {
        // Generate a mediaKey (32 bytes)
        $mediaKey = random_bytes(self::MEDIA_KEY_LENGTH);
        file_put_contents(self::DEFAULT_MEDIA_KEY_FILE_NAME, $mediaKey);

        return $mediaKey;
    }

    /**
     * @throws CorruptedMediaKeyException
     * @throws CryptException
     * @throws RandomException
     * @throws FileNotFoundException
     */
    protected function encryptStreamData(
        MediaTypeEnum $mediaType,
        ?string $keyFileName,
    ): string {
        if ($keyFileName === null) {
            //1.1  generate new mediaKey
            $mediaKey = $this->generateMediaKey();
        } else {
            //1.2 or use existing mediaKey
            $mediaKey = $this->getMediaKeyFromFile($keyFileName);
        }

        //2. Expand it
        $mediaKeyExpanded = $this->getExpandedMediaKey($mediaKey, $mediaType);

        //3. Split `mediaKeyExpanded`
        [$iv, $cipherKey, $macKey] = $this->splitExpandedKey($mediaKeyExpanded);
        $this->macKey = $macKey;
        $this->iv = $iv;

        //4. Encrypt the file
        $enc = $this->encrypt($cipherKey);

        //5. Sign `iv + enc` with `macKey`
        $mac = $this->getMac($iv, $enc, $macKey);

        //6. Append `mac` to the `enc`
        return $enc.$mac;
    }

    /**
     * @throws CryptException
     */
    protected function encrypt(string $cipherKey): string
    {
        // Initialize the encryption buffer
        $encryptedData = '';
        // Encrypt the stream data chunk by chunk
        while (! $this->stream->eof()) {
            // Read a chunk of data from the stream
            $chunk = $this->stream->read(self::BLOCK_SIZE);

            // Check if this is the last chunk
            $isLastChunk = $this->stream->eof();

            $options = OPENSSL_RAW_DATA;
            // Apply padding only if it's not the last chunk
            if (! $isLastChunk) {
                $options |= OPENSSL_ZERO_PADDING;
            }

            // Encrypt the chunk of data
            $encryptedChunk = openssl_encrypt(
                data: $chunk,
                cipher_algo:  self::CIPHER_ALGORITHM,
                passphrase: $cipherKey,
                options: $options,
                iv: $this->getCurrentIv(),
            );

            if ($encryptedChunk === false) {
                throw new CryptException('Failed to encrypt data: '.openssl_error_string());
            }

            // Append the encrypted chunk to the encrypted data
            $encryptedData .= $encryptedChunk;
            $this->updateIv($encryptedChunk);
        }

        return $encryptedData;
    }

    public function getSideCar(): ?string
    {
        $sidecar = null;
        if (in_array($this->mediaType->name, ['AUDIO', 'VIDEO'])) {
            $sidecar = $this->generateSidecar();
        }
        return $sidecar;
    }

    /**
     * This will generate the sidecar for the streamable media.
     */
    protected function generateSidecar(): string
    {
        // Initialize the sidecar buffer
        $sidecar = '';

        // Calculate the chunk size
        $chunkSize = 64 * 1024; // 64 KB
        $this->stream->rewind();
        // Read the stream chunk by chunk
        while (! $this->stream->eof()) {
            // Read a chunk of data from the stream
            $chunk = $this->stream->read($chunkSize + 16); // Add 16 bytes to accommodate the offset

            $hmac = hash_hmac(self::HASH_ALGORITHM, $this->iv.$chunk, $this->macKey, true);

            // Truncate the result to the first 10 bytes
            $mac = substr($hmac, 0, 10);

            // Append the signed chunk to the sidecar
            $sidecar .= $mac;
        }
        return $sidecar;
    }
}
