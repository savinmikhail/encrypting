<?php

namespace Mikhail\Encryptor;
require 'vendor/autoload.php';

use GuzzleHttp\Psr7\StreamDecoratorTrait;
use Psr\Http\Message\StreamInterface;
use Mikhail\Encryptor\Enums\MediaTypeEnum;
use Mikhail\Encryptor\Exceptions\CryptException;

class EncryptingStream extends Encryption implements StreamInterface
{
    use StreamDecoratorTrait;
    protected const BLOCK_SIZE = 16; // AES block size is 16 bytes (128 bits)
    protected const /*string*/ CIPHER_ALGORITHM = 'aes-256-cbc';

    public function __construct(protected StreamInterface $stream)
    {
    }

    public function isWritable(): false
    {
        return false;
    }

    public function read($length): string
    {
           return $this->encryptBlock($length);
    }

    private function encryptBlock(int $length): string
    {
        if ($this->stream->eof()) {
            return '';
        }
        $this->mediaType =  MediaTypeEnum::DOCUMENT;

        $count = ceil($length/self::BLOCK_SIZE);
        $encryptedData = '';
        $mediaKey = $this->generateMediaKey();

        //2. Expand it
        $mediaKeyExpanded = $this->getExpandedMediaKey($mediaKey);

        //3. Split `mediaKeyExpanded`
        [$iv, $cipherKey, $macKey] = $this->splitExpandedKey($mediaKeyExpanded);
        $this->macKey = $macKey;
        $this->iv = $iv;

        do {
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
            $count--;
        } while ($count > 0 || !$this->stream->eof());



        return $encryptedData;
    }

}
