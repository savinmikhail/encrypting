<?php

namespace Tests\Unit;

use GuzzleHttp\Psr7\Utils;
use src\DecryptingStream;
use src\EncryptingStream;
use src\Enums\MediaTypeEnum;

class EncryptionStreamTest extends BaseTestCase
{
    public function testEncryptionCorrectness()
    {
        // Arrange
        $plaintext = 'Hello, world!';
        $stream = Utils::streamFor($plaintext);
        $encryptingStream = new EncryptingStream($stream, MediaTypeEnum::DOCUMENT);

        // Act
        $encryptedData = $encryptingStream->read(strlen($plaintext));

        // Assert
        $this->assertNotEquals($plaintext, $encryptedData);

        $stream = Utils::streamFor($encryptedData);
        $decryptingStream = new DecryptingStream($stream, MediaTypeEnum::DOCUMENT);

        $decryptedData = $decryptingStream->read(strlen($encryptedData));

        $this->assertEquals($plaintext, $decryptedData);
    }

    public function testStreamReadingBehavior()
    {
        //        $this->markTestIncomplete();
        // Arrange
        $plaintext = 'Hello, world!';
        $stream = Utils::streamFor($plaintext);
        $encryptingStream = new EncryptingStream($stream, MediaTypeEnum::DOCUMENT);

        // Act
        $encryptedData = $encryptingStream->read(strlen($plaintext)); // Read 10 bytes

        // Assert
        $this->assertNotEmpty($encryptedData);
    }

    public function testErrorHandling()
    {
        $this->markTestIncomplete();

        // Arrange
        $invalidData = '';
        $stream = Utils::streamFor($invalidData);
        $encryptingStream = new EncryptingStream($stream, MediaTypeEnum::DOCUMENT);

        // Act
        $encryptedData = $encryptingStream->read(strlen($invalidData));
        //        dd($encryptedData);
        //& Assert
        $this->assertEmpty($encryptedData);
    }
}
