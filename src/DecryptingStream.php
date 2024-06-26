<?php

namespace Mikhail\Encryptor;

use GuzzleHttp\Psr7\StreamDecoratorTrait;
use Psr\Http\Message\StreamInterface;
use Mikhail\Encryptor\Enums\MediaTypeEnum;
use Mikhail\Encryptor\Exceptions\CryptException;

class DecryptingStream extends Decryption implements StreamInterface
{
    use StreamDecoratorTrait;

    public function __construct(
        protected StreamInterface $stream,
        protected MediaTypeEnum $mediaType,
        protected string $mediaKey,
    ) {
    }

    public function isWritable(): false
    {
        return false;
    }

    public function read($length): string
    {
        return $this->decryptBlock($length);
    }

    /**
     * @throws CryptException
     */
    protected function decryptBlock(int $length): string
    {
        //1. Obtain `mediaKey`.
        //2. Expand it
        $mediaKeyExpanded = $this->getExpandedMediaKey();

        //3. Split `mediaKeyExpanded`
        [$this->iv, $cipherKey, $this->macKey] = $this->splitExpandedKey($mediaKeyExpanded);

        //4. Obtain file and mac
//                [$file, $mac] = $this->getFileAndMacFromEncryptedMedia();
//                $this->stream = Utils::streamFor($file);

        //5. Validate media data
//                $this->validateMediaData($file, $mac);

        //6. Decrypt `file`
        $decryptedData = '';
        $count = ceil($length / self::BLOCK_SIZE);

        while ($count > 0 || ! $this->stream->eof()) {

            // Read a chunk of data from the stream
            $encryptedChunk = $this->stream->read(self::BLOCK_SIZE);
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

        if ($this->stream->eof()) {
            return $this->unpad($decryptedData);
        }

        return $decryptedData;

    }
}
