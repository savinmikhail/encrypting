<?php

namespace src;

use GuzzleHttp\Psr7\Utils;
use src\Exceptions\CorruptedMediaKeyException;
use src\Exceptions\CryptException;
use src\Exceptions\FileNotFoundException;

class Decryption extends Crypt
{
    protected string $macKey;

    protected function unpad($data): string
    {
        $padding = ord($data[strlen($data) - 1]);

        return substr($data, 0, -$padding);
    }

    /**
     * @throws CorruptedMediaKeyException
     * @throws CryptException
     * @throws FileNotFoundException
     */
    protected function decryptStreamData(string $mediaKey): string
    {
        //1. Obtain `mediaKey`.
        if (strlen($mediaKey) !== self::MEDIA_KEY_LENGTH) {
            throw new CorruptedMediaKeyException('mediaKey is not '.self::MEDIA_KEY_LENGTH.' bytes');
        }

        //2. Expand it
        $mediaKeyExpanded = $this->getExpandedMediaKey($mediaKey);

        //3. Split `mediaKeyExpanded`
        [$iv, $cipherKey, $this->macKey] = $this->splitExpandedKey($mediaKeyExpanded);
        $this->iv = $iv;

        //4. Obtain file and mac
        [$file, $mac] = $this->getFileAndMacFromEncryptedMedia();
        $this->stream = Utils::streamFor($file);

        //5. Validate media data
        $this->validateMediaData($file, $mac, $iv, $this->macKey);

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
    protected function validateMediaData(
        string $encryptedFile,
        string $mac,
        string $iv,
        string $macKey,
    ): void {
        // Validate media data with HMAC by signing iv + encryptedFile with macKey using SHA-256
        $computedMac = $this->getMac($iv, $encryptedFile, $macKey);

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

            //the last chunk is always empty string, so it is impossible to decrypt
            $isLastChunk = $this->stream->eof();

            if ($isLastChunk) {
                break;
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

            $decryptedData .= $decryptedChunk;
            $this->updateIv($encryptedChunk);
        }

        return $this->unpad($decryptedData);
    }

    /**
     * принимает зашифрованный методом encryptFile файл, возвращает дешифрованную последоватлеьность байтов
     */
    public function decryptFile(
        string $filePath,
        /** здесь либо пользователь предоставляет нужный ключ, либо берем потенциально последний сгенеренный */
        string $mediaKey,
    ): string {
        $this->stream = $this->getStreamFromFile($filePath);
        $this->mediaType = $this->getMediaType($filePath);

        return $this->decryptStreamData($mediaKey);
    }
}
