<?php

declare(strict_types=1);

namespace src;

use GuzzleHttp\Psr7\Stream;
use Psr\Http\Message\StreamInterface;
use Random\RandomException;
use src\Enums\MediaTypeEnum;
use src\Exceptions\CorruptedMediaKeyException;
use src\Exceptions\CryptException;
use src\Exceptions\EmptyFileException;
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
     * @throws CryptException
     */
    private function decrypt(StreamInterface $stream, string $cipherKey, string $iv): string
    {
        // Initialize the decryption buffer
        $decryptedData = '';


        //        $decryptedData = openssl_decrypt(
        //            $file,
        //            self::CIPHER_ALGORITHM,
        //            $cipherKey,
        //            OPENSSL_RAW_DATA,
        //            $iv
        //        );
        //
        //        if ($decryptedData === false) {
        //            throw new CryptException('Decrypted data failed: '.openssl_error_string());
        //        }
        $this->iv = $iv;
        //дешифрование чанками не работает
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

    private function unpad($data): string
    {
        $padding = ord($data[strlen($data) - 1]);

        return substr($data, 0, -$padding);
    }

    /**
     * You can then call this method after encrypting the media file,
     * passing the encrypted stream and the macKey as parameters.
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

            // Sign the chunk with macKey using HMAC SHA-256
            $mac = hash_hmac(self::HASH_ALGORITHM, $chunk, $macKey, true);

            // Truncate the result to the first 10 bytes
            $mac = substr($mac, 0, 10);

            // Append the signed chunk to the sidecar
            $sidecar .= $mac;
        }

        return $sidecar;
    }
}
