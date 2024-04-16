<?php

namespace src;

use GuzzleHttp\Psr7\StreamDecoratorTrait;
use Psr\Http\Message\StreamInterface;
use Random\RandomException;
use src\Enums\MediaTypeEnum;
use src\Exceptions\CorruptedMediaKeyException;
use src\Exceptions\CryptException;

class EncryptingStream extends Encryption implements StreamInterface
{
    use StreamDecoratorTrait;

    public function __construct(
        protected StreamInterface $stream,
        protected MediaTypeEnum $mediaType,
        protected ?string $mediaKey = null,
    ) {
    }

    public function isWritable(): false
    {
        return false;
    }

    public function read($length): string
    {
        return $this->encryptBlock($length);
    }

    protected function getBlockAmount(int $length): int
    {
        return ceil($length / self::BLOCK_SIZE);
    }

    /**
     * @throws CorruptedMediaKeyException
     * @throws CryptException
     * @throws RandomException
     */
    private function encryptBlock(int $length): string
    {
        if ($this->stream->eof()) {
            return '';
        }
        //1. Use provided media key or generate the new one
        $this->checkMediaKey();

        //2. Expand it
        $mediaKeyExpanded = $this->getExpandedMediaKey();

        //3. Split `mediaKeyExpanded`
        [$this->iv , $cipherKey, $this->macKey] = $this->splitExpandedKey($mediaKeyExpanded);

        $count = $this->getBlockAmount($length);
        $encryptedData = '';

        while ($count > 0 || ! $this->stream->eof()) {
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
            $count--;
        }

        //5. Sign `iv + enc` with `macKey`
        $mac = $this->getMac($this->iv, $encryptedData, $this->macKey);

        //6. Append `mac` to the `enc`
        return $encryptedData.$mac;
    }
}
