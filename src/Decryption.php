<?php

namespace src;

use GuzzleHttp\Psr7\Utils;
use Psr\Http\Message\StreamInterface;
use src\Enums\MediaTypeEnum;
use src\Exceptions\CorruptedMediaKeyException;
use src\Exceptions\CryptException;

class Decryption extends Crypt
{
    protected string $mediaKey;

    protected function unpad($data): string
    {
        $padding = ord($data[strlen($data) - 1]);

        return substr($data, 0, -$padding);
    }

    /**
     * @throws CorruptedMediaKeyException
     */
    protected function checkMediaKey(): void
    {
        if (strlen($this->mediaKey) !== self::MEDIA_KEY_LENGTH) {
            throw new CorruptedMediaKeyException('mediaKey is not '.self::MEDIA_KEY_LENGTH.' bytes');
        }
    }

    /**
     * @throws CorruptedMediaKeyException
     * @throws CryptException
     */
    public function decryptStream(
        StreamInterface $stream,
        string $mediaKey,
        MediaTypeEnum $mediaType,
    ): string {
        $this->stream = $stream;
        $this->mediaType = $mediaType;
        $this->mediaKey = $mediaKey;

        //1. Obtain `mediaKey`.
        $this->checkMediaKey();

        //2. Expand it
        //3. Split `mediaKeyExpanded`
        [$iv, $cipherKey, $this->macKey] = $this->splitExpandedKey($this->getExpandedMediaKey());
        $this->iv = $iv;

        //4. Obtain file and mac
        [$file, $mac] = $this->getFileAndMacFromEncryptedMedia();
        $this->stream = Utils::streamFor($file);

        //5. Validate media data
        $this->validateMediaData($file, $mac);

        //6. Decrypt `file`
        return $this->decrypt($cipherKey);
    }

    protected function getFileAndMacFromEncryptedMedia(): array
    {
        // Read the stream and split the encrypted media data and MAC
        $mediaData = (string) $this->stream;

        // Extract the encrypted file data
        $encryptedFile = substr($mediaData, 0, -self::MAC_LENGTH);

        // Rewind the stream to its original position
        $this->stream->rewind();

        return [$encryptedFile, $this->getMacFromEncryptedMedia()];
    }

    protected function getMacFromEncryptedMedia(): string
    {
        $mediaLength = $this->stream->getSize(); // Assuming the stream supports size

        // Seek to the beginning of the MAC (excluding data)
        $this->stream->seek($mediaLength - self::MAC_LENGTH);

        // Read the MAC
        $mac = $this->stream->read(self::MAC_LENGTH);
        $this->stream->rewind();

        return $mac;
    }

    /**
     * @throws CryptException
     */
    protected function validateMediaData(string $encryptedFile,string $mac): void
    {
        // Validate media data with HMAC by signing iv + encryptedFile with macKey using SHA-256
        $computedMac = $this->getMac($this->iv, $encryptedFile, $this->macKey);

        // Compare the computed MAC with the received MAC
        if (! hash_equals($mac, $computedMac)) {
            throw new CryptException('MAC validation failed');
        }
    }

    /**
     * @throws CryptException
     */
    protected function decrypt(string $cipherKey): string
    {
        $decryptedData = '';

        while (! $this->stream->eof()) {
            // Read a chunk of data from the stream
            $encryptedChunk = $this->stream->read(self::BLOCK_SIZE);

            $decryptedChunk = $this->decryptChunk($cipherKey, $encryptedChunk);

            $decryptedData .= $decryptedChunk;
            $this->updateIv($encryptedChunk);
        }

        return $this->unpad($decryptedData);
    }

    /**
     * @throws CryptException
     */
    protected function decryptChunk(string $cipherKey, string $encryptedChunk): string
    {
        //the last chunk is always empty string, so it is impossible to decrypt
        if ($this->stream->eof()) {
            return '';
        }
        $decryptedChunk = openssl_decrypt(
            data: $encryptedChunk,
            cipher_algo: self::CIPHER_ALGORITHM,
            passphrase: $cipherKey,
            options: OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
            iv: $this->getCurrentIv(),
        );

        if ($decryptedChunk === false) {
            throw new CryptException('Decrypted data failed: '.openssl_error_string());
        }
        return $decryptedChunk;
    }
}
