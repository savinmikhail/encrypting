<?php

namespace Mikhail\Tests\Encryption;
require __DIR__ . '/../vendor/autoload.php';
require __DIR__ . '/../src/EncryptingStream.php';

use GuzzleHttp\Psr7\Utils;
use Mikhail\Encryptor\DecryptingStream;
use Mikhail\Encryptor\EncryptingStream;
use PHPUnit\Framework\TestCase;

class EncryptionStreamTest extends TestCase
{
    public function testEncryptionCorrectness()
    {
        // Arrange
        $plaintext = 'Hello, world!';
        $stream = Utils::streamFor($plaintext);
        $encryptingStream = new EncryptingStream($stream);

        // Act
        $encryptedData = $encryptingStream->read(strlen($plaintext));

        // Assert
        $this->assertNotEquals($plaintext, $encryptedData);

        $stream = Utils::streamFor($encryptedData);
        $decryptingStream = new DecryptingStream($stream);
        $decryptedData = $decryptingStream->read(strlen($encryptedData));

        $this->assertEquals($plaintext, $decryptedData);

    }

    public function testStreamReadingBehavior()
    {
//        $this->markTestIncomplete();
        // Arrange
        $plaintext = 'Hello, world!';
        $stream = Utils::streamFor($plaintext);
        $encryptingStream = new EncryptingStream($stream);

        // Act
        $encryptedData = $encryptingStream->read(10); // Read 10 bytes

        // Assert
        $this->assertNotEmpty($encryptedData);
    }

    public function testErrorHandling()
    {
        $this->markTestIncomplete();

        // Arrange
        $invalidData = '';
        $stream = Utils::streamFor($invalidData);
        $encryptingStream = new EncryptingStream($stream);

        // Act
        $encryptedData = $encryptingStream->read(10);
//        dd($encryptedData);
        //& Assert
        $this->assertEmpty($encryptedData);
    }
}
