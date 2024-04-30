<?php

namespace Mikhail\Tests\Encryptor;

use GuzzleHttp\Psr7\Utils;
use Mikhail\Encryptor\DecryptingStream;
use Mikhail\Encryptor\EncryptingStream;
use Mikhail\Encryptor\Enums\MediaTypeEnum;

class EncryptionStreamTest extends BaseTestCase
{
    public function testEncryptionCorrectness(): void
    {
        // Arrange
        $plaintext = str_repeat('Hello, world!',1000);
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

    public function testEncryptForImage(): void
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

    public function testDecryptForImage(): void
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

    public function testEncryptionWithAudio(): void
    {
        $stream =  $this->getStreamFromFile(self::SAMPLES_FILES_FOLDER.'AUDIO.mp3');
        $encryptingStream = new EncryptingStream(
            $stream,
            MediaTypeEnum::AUDIO,
            file_get_contents(self::SAMPLES_FILES_FOLDER.'AUDIO.key')
        );

        file_put_contents(
            self::TEST_FILES_FOLDER.'audioEnc.mp3',
            $encryptingStream->read($encryptingStream->getSize())
        );

        $originalHash = hash_file('sha256', self::SAMPLES_FILES_FOLDER.'audioEnc.mp3');
        $encryptedHash = hash_file('sha256', self::TEST_FILES_FOLDER.'audioEnc.mp3');

        $this->assertEquals($originalHash, $encryptedHash);
    }

    public function testDecryptionWithAudio(): void
    {
        $stream =  $this->getStreamFromFile(self::SAMPLES_FILES_FOLDER.'AUDIO.mp3');

         $decryptingStream = new DecryptingStream(
             $stream,
             MediaTypeEnum::AUDIO,
             file_get_contents(self::SAMPLES_FILES_FOLDER.'AUDIO.key')
         );

        file_put_contents(
            self::TEST_FILES_FOLDER.'AUDIO.mp3',
            $decryptingStream->read($decryptingStream->getSize()),
        );

        $originalHash = hash_file('sha256', self::SAMPLES_FILES_FOLDER.'AUDIO.mp3');
        $decryptedHash = hash_file('sha256', self::TEST_FILES_FOLDER.'AUDIO.mp3');

        $this->assertEquals($originalHash, $decryptedHash);
    }

    public function testEncryptionWithVideo(): void
    {
        $stream =  $this->getStreamFromFile(self::SAMPLES_FILES_FOLDER.'VIDEO.mp4');
        $encryptingStream = new EncryptingStream(
            $stream,
            MediaTypeEnum::VIDEO,
            mediaKey:  file_get_contents(self::SAMPLES_FILES_FOLDER.'VIDEO.key')
        );

        file_put_contents(
            self::TEST_FILES_FOLDER.'videoEnc.mp4',
            data: $encryptingStream->read($encryptingStream->getSize()),
        );

        $originalHash = hash_file('sha256', self::SAMPLES_FILES_FOLDER.'videoEnc.mp4');
        $encryptedHash = hash_file('sha256', self::TEST_FILES_FOLDER.'videoEnc.mp4');

        $this->assertEquals($originalHash, $encryptedHash);
    }

    public function testDecryptionWithVideo(): void
    {
        $stream =  $this->getStreamFromFile(self::SAMPLES_FILES_FOLDER.'videoEnc.mp4');

        $decryptingStream = new DecryptingStream(
            $stream,
            MediaTypeEnum::VIDEO,
            file_get_contents(self::SAMPLES_FILES_FOLDER.'VIDEO.KEY')
        );

        file_put_contents(
            self::TEST_FILES_FOLDER.'VIDEO.mp4',
            $decryptingStream->read($decryptingStream->getSize()),
        );

        $originalHash = hash_file('sha256', self::SAMPLES_FILES_FOLDER.'VIDEO.mp4');
        $decryptedHash = hash_file('sha256', self::TEST_FILES_FOLDER.'VIDEO.mp4');

        $this->assertEquals($originalHash, $decryptedHash);
    }

    public function testDecryptionWithImageFromSamples(): void
    {
        $stream =  $this->getStreamFromFile(self::SAMPLES_FILES_FOLDER.'videoEnc.mp4');

        $decryptingStream = new DecryptingStream(
            $stream,
            MediaTypeEnum::IMAGE,
            file_get_contents(self::SAMPLES_FILES_FOLDER.'IMAGE.key')
        );

        file_put_contents(
            self::TEST_FILES_FOLDER.'IMAGE.jpeg',
            $decryptingStream->read($decryptingStream->getSize()),
        );

        $originalHash = hash_file('sha256', self::SAMPLES_FILES_FOLDER.'IMAGE.jpeg');
        $decryptedHash = hash_file('sha256', self::TEST_FILES_FOLDER.'IMAGE.jpeg');

        $this->assertEquals($originalHash, $decryptedHash);
    }
}
