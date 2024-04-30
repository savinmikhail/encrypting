<?php

namespace Mikhail\Tests\Encryptor;

use GuzzleHttp\Psr7\Utils;
use Mikhail\Encryptor\DecryptingStream;
use Mikhail\Encryptor\EncryptingStream;
use Mikhail\Encryptor\Enums\MediaTypeEnum;

class EncryptionStreamTest extends BaseTestCase
{
    public function testEncryptionCorrectness()
    {
        // Arrange
        $plaintext = str_repeat('Hello, world!',10);
        $stream = Utils::streamFor($plaintext);
        $encryptingStream = new EncryptingStream($stream, MediaTypeEnum::DOCUMENT);

        // Act
        $encryptedData = $encryptingStream->read(strlen($plaintext));

        // Assert
        $this->assertNotEquals($plaintext, $encryptedData);

        $stream = Utils::streamFor($encryptedData);
        $decryptingStream = new DecryptingStream(
            $stream,
            MediaTypeEnum::DOCUMENT,
            file_get_contents('mediaKey.txt')
        );

        $decryptedData = $decryptingStream->read(strlen($encryptedData));

        $this->assertEquals($plaintext, $decryptedData);
    }

    public function testEncryptForImage()
    {
        $stream =  $this->getStreamFromFile(self::SAMPLES_FILES_FOLDER.'IMAGE.jpeg');
        $encryptingStream = new EncryptingStream(
            $stream,
            MediaTypeEnum::IMAGE,
            file_get_contents(self::SAMPLES_FILES_FOLDER.'IMAGE.key')
        );

        file_put_contents(
            self::TEST_FILES_FOLDER.'imageEnc.jpeg',
            $encryptingStream->read($encryptingStream->getSize())
        );

        $originalHash = hash_file('sha256', self::SAMPLES_FILES_FOLDER.'imageEnc.jpeg');
        $encryptedHash = hash_file('sha256', self::TEST_FILES_FOLDER.'imageEnc.jpeg');

        $this->assertEquals($originalHash, $encryptedHash);
    }

    public function testDecryptForImage()
    {
        $stream =  $this->getStreamFromFile(self::SAMPLES_FILES_FOLDER.'IMAGE.jpeg');
        $decryptingStream = new DecryptingStream(
            $stream,
            MediaTypeEnum::IMAGE,
            file_get_contents(self::SAMPLES_FILES_FOLDER.'IMAGE.key')
        );

        file_put_contents(
            self::TEST_FILES_FOLDER.'imageDec.jpeg',
            $decryptingStream->read($decryptingStream->getSize())
        );

        $originalHash = hash_file('sha256', self::SAMPLES_FILES_FOLDER.'IMAGE.jpeg');
        $decryptedHash = hash_file('sha256', self::TEST_FILES_FOLDER.'IMAGE.jpeg');

        $this->assertEquals($originalHash, $decryptedHash);
    }
}
