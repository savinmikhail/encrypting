<?php

namespace src;

use GuzzleHttp\Psr7\Stream;
use Psr\Http\Message\StreamInterface;
use src\Enums\MediaTypeEnum;
use src\Exceptions\CorruptedMediaKeyException;
use src\Exceptions\CryptException;
use src\Exceptions\FileNotFoundException;

class Decryption extends Crypt
{
    /**
     * принимает зашифрованный методом encryptFile файл, возвращает дешифрованную последоватлеьность байтов
     */
    public function decryptFile(
        string $filePath,
        /** здесь либо пользователь предоставляет нужный ключ, либо берем потенциально последний сгенеренный */
        string $keyFileName = self::DEFAULT_MEDIA_KEY_FILE_NAME,
    ): string {
        $stream = $this->getStreamFromFile($filePath);
        $mediaType = $this->getMediaType($filePath);

        // Decrypt the stream data one by one
        return $this->decryptStreamData($stream, $mediaType, $keyFileName);
    }

    /**
     * @throws CorruptedMediaKeyException
     * @throws CryptException
     * @throws FileNotFoundException
     */
    private function decryptStreamData(StreamInterface $stream, MediaTypeEnum $mediaType, string $keyFileName): string
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
        return $this->decrypt($this->stringToStream($file), $cipherKey, $iv);
    }

    private function stringToStream(string $data): StreamInterface
    {
        $stream = fopen('php://temp', 'r+');
        fwrite($stream, $data);
        rewind($stream);

        return new Stream($stream);
    }

    /**
     * @throws CryptException
     */
    private function decrypt(StreamInterface $stream, string $cipherKey, string $iv): string
    {
        // Initialize the decryption buffer
        $decryptedData = '';

        $this->iv = $iv;
        // Decrypt the stream data chunk by chunk
        while (! $stream->eof()) {

            // Read a chunk of data from the stream
            $encryptedChunk = $stream->read(self::BLOCK_SIZE);
            $isLastChunk = $stream->eof();

            if ($isLastChunk) {
                break;
            }
            // Decrypt the chunk of data
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
            // Append the decrypted chunk to the decrypted data
            $decryptedData .= $decryptedChunk;
            $this->updateIv($encryptedChunk);
        }

        // Unpad the decrypted file
        return $this->unpad($decryptedData);
    }

    /**
     * @throws CryptException
     */
    private function validateMediaData(
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

    private function getFileAndMacFromEncryptedMedia(StreamInterface $stream): array
    {
        // Get the current position of the stream
        $currentPosition = $stream->tell();

        // Read the stream and split the encrypted media data and MAC
        $mediaData = (string) $stream;

        // Extract the encrypted file data
        $encryptedFile = substr($mediaData, 0, -self::MAC_LENGTH);

        // Extract the MAC from the end of the encrypted data
        $mac = substr($mediaData, -self::MAC_LENGTH);

        // Rewind the stream to its original position
        $stream->seek($currentPosition);

        return [$encryptedFile, $mac];
    }

    private function unpad($data): string
    {
        $padding = ord($data[strlen($data) - 1]);

        return substr($data, 0, -$padding);
    }
}
