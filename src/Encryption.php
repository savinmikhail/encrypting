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

readonly class Encryption
{
    private const /*string*/ HASH_ALGORITHM = 'sha256';

    private const /*string*/ CIPHER_ALGORITHM = 'aes-256-cbc';

    private const /*int*/ MEDIA_KEY_LENGTH = 32;

    private const /*int*/ MEDIA_KEY_EXPANDED_LENGTH = 112;

    private const /*string*/ DEFAULT_MEDIA_KEY_FILE_NAME = 'mediaKey.txt';

    private const /*int*/ MAC_LENGTH = 10;

    private const /*int*/ CHUNK_LENGTH = 10_000_000; //todo: доделать кусочное шифрование дешифрование

    private const BLOCK_SIZE = 16; // AES block size is 16 bytes (128 bits)

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
     * @throws EmptyFileException
     * @throws FileNotFoundException
     */
    private function getStreamFromFile(string $filePath): StreamInterface
    {
        if (! file_exists($filePath)) {
            throw new FileNotFoundException("File $filePath does not exist");
        }
        // Check if the file is empty
        if (filesize($filePath) === 0) {
            throw new EmptyFileException('File is empty');
        }
        $stream = fopen($filePath, 'r');
        fseek($stream, 0);

        return new Stream($stream);
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
     * @throws FileNotFoundException
     */
    private function getMediaKeyFromFile(?string $keyFileName): string
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
        $encryptedStream = $enc.$mac;

        return $encryptedStream;
    }

    /**
     * @throws CryptException
     */
    private function encrypt(StreamInterface $stream, string $cipherKey, string $iv): string
    {
        // Initialize the encryption buffer
        $encryptedData = '';

        // Encrypt the stream data chunk by chunk
        while (! $stream->eof()) {
            // Read a chunk of data from the stream
            $chunk = $stream->read(self::CHUNK_LENGTH);

            // Apply PKCS7 padding to the chunk
            //            $padding = self::BLOCK_SIZE - strlen($chunk) % self::BLOCK_SIZE;
            //            $chunk .= str_repeat(chr($padding), $padding);

            // Encrypt the chunk of data
            $encryptedChunk = openssl_encrypt(
                data: $chunk,
                cipher_algo: self::CIPHER_ALGORITHM,
                passphrase: $cipherKey,
                options: OPENSSL_RAW_DATA,
                iv: $iv
            );

            if ($encryptedChunk === false) {
                throw new CryptException('Failed to encrypt data: '.openssl_error_string());
            }
            // Append the encrypted chunk to the encrypted data
            $encryptedData .= $encryptedChunk;
        }

        return $encryptedData;
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
        $decryptedFile = $this->decrypt($file, $cipherKey, $iv);

        return $decryptedFile;
    }

    /**
     * @throws CryptException
     */
    private function decrypt(string $file, string $cipherKey, string $iv): string
    {
        // Initialize the decryption buffer
        //        $decryptedData = '';

        $decryptedData = openssl_decrypt(
            $file,
            self::CIPHER_ALGORITHM,
            $cipherKey,
            OPENSSL_RAW_DATA,
            $iv
        );

        if ($decryptedData === false) {
            throw new CryptException('Decrypted data failed: '.openssl_error_string());
        }

        //дешифрование чанками не работает
        // Decrypt the stream data chunk by chunk
        //        while (! $stream->eof()) {
        //
        //            // Read a chunk of data from the stream
        //            $chunk = $stream->read(self::CHUNK_LENGTH);
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
        //        return $this->unpad($decryptedData);
        return $decryptedData;
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
            self::MEDIA_KEY_EXPANDED_LENGTH,
            $mediaType->value,
        );
    }

    private function getMac(string $iv, string $encryptedData, string $macKey): string
    {
        // Take the first 10 bytes of the HMAC as the MAC
        return substr(
            $this->calculateHmac($iv, $encryptedData, $macKey),
            0,
            self::MAC_LENGTH,
        );
    }

    private function calculateHmac(string $iv, string $encryptedData, string $macKey): string
    {
        // Calculate HMAC for iv + encrypted data using macKey
        return hash_hmac(
            self::HASH_ALGORITHM,
            $iv.$encryptedData,
            $macKey,
            true
        );
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
