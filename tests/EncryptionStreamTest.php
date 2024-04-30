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
        $plaintext = 'Hello, world!gllkjklnk;njknk;nk;nk;nk;jknknkjnjnkjn';
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
        $stream =  $this->getStreamFromFile(self::SAMPLES_FILES_FOLDER.'VIDEO.mp4');
        $encryptingStream = new EncryptingStream(
            $stream,
            MediaTypeEnum::VIDEO,
            file_get_contents(self::SAMPLES_FILES_FOLDER.'VIDEO.key')
        );

        file_put_contents(self::TEST_FILES_FOLDER.'videoEnc.mp4', $encryptingStream->read($encryptingStream->getSize()));

        $originalHash = hash_file('sha256', self::SAMPLES_FILES_FOLDER.'videoEnc.mp4');
        $encryptedHash = hash_file('sha256', self::TEST_FILES_FOLDER.'videoEnc.mp4');

        $this->assertEquals($originalHash, $encryptedHash);
    }

    public function testDecryptForImage()
    {
        $stream =  $this->getStreamFromFile(self::SAMPLES_FILES_FOLDER.'VIDEO.mp4');
        $decryptingStream = new DecryptingStream(
            $stream,
            MediaTypeEnum::VIDEO,
            file_get_contents(self::SAMPLES_FILES_FOLDER.'VIDEO.key')
        );

        file_put_contents(self::TEST_FILES_FOLDER.'videoEnc.mp4', $decryptingStream->read($decryptingStream->getSize()));

        $originalHash = hash_file('sha256', self::SAMPLES_FILES_FOLDER.'videoEnc.mp4');
        $decryptedHash = hash_file('sha256', self::TEST_FILES_FOLDER.'videoEnc.mp4');

        $this->assertEquals($originalHash, $decryptedHash);
    }
}
