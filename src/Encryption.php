<?php

declare(strict_types=1);

namespace src;

use Psr\Http\Message\StreamInterface;
use Random\RandomException;
use src\Enums\MediaTypeEnum;
use src\Exceptions\CorruptedMediaKeyException;
use src\Exceptions\CryptException;
use src\Exceptions\FileNotFoundException;

class Encryption extends Crypt
{
    /**
     * принимает файл, возвращает строоку зашифрованных байтов
     */
    public function encryptFile(
        string $filePath,
        /** здесь ключ опционален, если не предоставлен, то сгенерим сами */
        ?string $keyFileName = null,
    ): string {
        $stream = $this->getStreamFromFile($filePath);
        $mediaType = $this->getMediaType($filePath);

        return $this->encryptStreamData($stream, $mediaType, $keyFileName);
    }

    /**
     * @throws RandomException
     */
    private function generateMediaKey(): string
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
    private function encryptStreamData(
        StreamInterface $stream,
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

        //4. Encrypt the file
        $enc = $this->encrypt($stream, $cipherKey, $iv);

        //5. Sign `iv + enc` with `macKey`
        $mac = $this->getMac($iv, $enc, $macKey);

        //6. Append `mac` to the `enc`
        return $enc.$mac;
    }

    /**
     * @throws CryptException
     */
    private function encrypt(StreamInterface $stream, string $cipherKey, string $iv): string
    {
        // Initialize the encryption buffer
        $encryptedData = '';
        $this->iv = $iv;
        // Encrypt the stream data chunk by chunk
        while (! $stream->eof()) {
            // Read a chunk of data from the stream
            $chunk = $stream->read(self::BLOCK_SIZE);

            // Check if this is the last chunk
            $isLastChunk = $stream->eof();

            $options = OPENSSL_RAW_DATA;
            // Apply padding only if it's not the last chunk
            if (! $isLastChunk) {
                $options |= OPENSSL_ZERO_PADDING;
            }

            // Encrypt the chunk of data
            $encryptedChunk = openssl_encrypt(
                $chunk,
                self::CIPHER_ALGORITHM,
                $cipherKey,
                $options,
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
    /**
     * This will generate the sidecar for the streamable media.
     */
    private function generateSidecar(StreamInterface $stream, string $macKey): string
    {
        // Initialize the sidecar buffer
        $sidecar = '';

        // Calculate the chunk size
        $chunkSize = 64 * 1024; // 64 KB

        // Read the stream chunk by chunk
        while (! $stream->eof()) {
            // Read a chunk of data from the stream
            $chunk = $stream->read($chunkSize + 16); // Add 16 bytes to accommodate the offset

            $mac = hash_hmac(self::HASH_ALGORITHM, $chunk, $macKey, true);

            // Truncate the result to the first 10 bytes
            $mac = substr($mac, 0, 10);

            // Append the signed chunk to the sidecar
            $sidecar .= $mac;
        }

        return $sidecar;
    }
}
