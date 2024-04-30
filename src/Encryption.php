<?php

declare(strict_types=1);

namespace Mikhail\Encryptor;

use Mikhail\Encryptor\Enums\MediaTypeEnum;
use Mikhail\Encryptor\Exceptions\CorruptedMediaKeyException;
use Mikhail\Encryptor\Exceptions\CryptException;
use Psr\Http\Message\StreamInterface;
use Random\RandomException;

class Encryption extends Crypt
{
    protected const /*int*/ SIDECAR_OFFSET = 16;
    protected ?string $mediaKey;
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
     * @throws RandomException
     */
    protected function checkMediaKey(): void
    {
        if ($this->mediaKey === null) {
            //1.1  generate new mediaKey
            $this->mediaKey = $this->generateMediaKey();
        }
        //1.2 or use existing mediaKey
        if (strlen($this->mediaKey) !== self::MEDIA_KEY_LENGTH) {
            throw new CorruptedMediaKeyException('mediaKey is not '.self::MEDIA_KEY_LENGTH.' bytes');
        }
    }

    /**
     * @throws CorruptedMediaKeyException
     * @throws CryptException
     * @throws RandomException
     */
    public function encryptStream(
        StreamInterface $stream,
        MediaTypeEnum $mediaType,
        /** здесь ключ опционален, если не предоставлен, то сгенерим сами */
        ?string $mediaKey = null,
    ): string {
        $this->stream = $stream;
        $this->mediaType = $mediaType;
        $this->mediaKey = $mediaKey;

        $this->checkMediaKey();
        //2. Expand it
        //3. Split `mediaKeyExpanded`
        [$iv, $cipherKey, $this->macKey] = $this->splitExpandedKey($this->getExpandedMediaKey());
        $this->iv = $iv;

        //4. Encrypt the file
        $enc = $this->encrypt($cipherKey);

        //5. Sign `iv + enc` with `macKey`
        $mac = $this->getMac($iv, $enc, $this->macKey);

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

            // Encrypt the chunk of data
            $encryptedChunk = openssl_encrypt(
                data: $chunk,
                cipher_algo: self::CIPHER_ALGORITHM,
                passphrase: $cipherKey,
                options: $this->getOptions(),
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

    protected function getOptions(): int
    {
        $options = OPENSSL_RAW_DATA;
        // Apply padding only if it's not the last chunk
        if (! $this->stream->eof()) {
            $options |= OPENSSL_ZERO_PADDING;
        }

        return $options;
    }

    public function getSideCar(): ?string
    {
        $sidecar = null;
        if (in_array($this->mediaType->name, [
            MediaTypeEnum::AUDIO->name,
            MediaTypeEnum::VIDEO->name,
        ])) {
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
            $chunk = $this->stream->read($chunkSize + self::SIDECAR_OFFSET); // Add 16 bytes to accommodate the offset

            $hmac = hash_hmac(self::HASH_ALGORITHM, $this->iv.$chunk, $this->macKey, true);

            // Truncate the result to the first 10 bytes
            $mac = substr($hmac, 0, self::MAC_LENGTH);

            // Append the signed chunk to the sidecar
            $sidecar .= $mac;
        }

        return $sidecar;
    }
}
