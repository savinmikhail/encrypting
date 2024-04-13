<?php

namespace Tests\Unit;

use PHPUnit\Framework\TestCase;
use src\Encryption;

class EncryptionTest extends TestCase
{
    private const /*string*/ TEST_FILES_FOLDER = 'tests/Unit/testFiles/';

    private const /*string*/ SAMPLES_FILES_FOLDER = 'samples/';

    private Encryption $encryption;

    public function setUp(): void
    {
        $this->encryption = new Encryption();
    }

    public function testEncryptionWithImage()
    {
        $encryptor = new Encryption();
        // Decrypt the encrypted stream data
        $decryptedString = $encryptor->encryptFile(
            self::SAMPLES_FILES_FOLDER.'IMAGE.jpeg',
            self::SAMPLES_FILES_FOLDER.'IMAGE.key'
        );

        file_put_contents(self::TEST_FILES_FOLDER.'imageEnc.jpeg', $decryptedString);

        // Calculate hashes of the original and decrypted files
        $originalHash = hash_file('sha256', self::SAMPLES_FILES_FOLDER.'imageEnc.jpeg');
        $encryptedHash = hash_file('sha256', self::TEST_FILES_FOLDER.'imageEnc.jpeg');

        $this->assertEquals($originalHash, $encryptedHash);
        // Assert that the decrypted string matches the original input string
        //        $this->assertEquals(file_get_contents('samples/imageEnc.jpeg'), file_get_contents('imageEnc.jpeg'));
    }

    public function testEncryptionWithAudio()
    {
        $encryptor = new Encryption();
        // Decrypt the encrypted stream data
        $decryptedString = $encryptor->encryptFile(
            self::SAMPLES_FILES_FOLDER.'AUDIO.mp3',
            self::SAMPLES_FILES_FOLDER.'AUDIO.key'
        );

        file_put_contents(self::TEST_FILES_FOLDER.'audioEnc.mp3', $decryptedString);

        // Calculate hashes of the original and decrypted files
        $originalHash = hash_file('sha256', self::SAMPLES_FILES_FOLDER.'audioEnc.mp3');
        $encryptedHash = hash_file('sha256', self::TEST_FILES_FOLDER.'audioEnc.mp3');
        $this->assertEquals($originalHash, $encryptedHash);
        // Assert that the decrypted string matches the original input string
        //        $this->assertEquals(file_get_contents('samples/AUDIO.mp3'), file_get_contents('AUDIO.mp3'));
    }

    public function testEncryptionWithVideo()
    {
        $encryptor = new Encryption();
        // Decrypt the encrypted stream data
        $decryptedString = $encryptor->encryptFile(
            self::SAMPLES_FILES_FOLDER.'VIDEO.mp4',
            self::SAMPLES_FILES_FOLDER.'VIDEO.key'
        );

        file_put_contents(self::TEST_FILES_FOLDER.'videoEnc.mp4', $decryptedString);

        // Calculate hashes of the original and decrypted files
        $originalHash = hash_file('sha256', self::SAMPLES_FILES_FOLDER.'videoEnc.mp4');
        $encryptedHash = hash_file('sha256', self::TEST_FILES_FOLDER.'videoEnc.mp4');
        $this->assertEquals($originalHash, $encryptedHash);
        // Assert that the decrypted string matches the original input string
        //        $this->assertEquals(file_get_contents('samples/AUDIO.mp3'), file_get_contents('AUDIO.mp3'));
    }

    public function testSideCarWithVideo()
    {
        //act
        $this->encryption->encryptFile(
            self::SAMPLES_FILES_FOLDER.'VIDEO.mp4',
            self::SAMPLES_FILES_FOLDER.'VIDEO.key'
        );

        $sideCar = $this->encryption->getSideCar();

//        dd($sideCar, file_get_contents(self::SAMPLES_FILES_FOLDER.'VIDEO.sidecar'));
        file_put_contents(self::TEST_FILES_FOLDER.'video.sidecar', $sideCar);

        //assert
        $this->assertEquals(
            file_get_contents(self::SAMPLES_FILES_FOLDER.'VIDEO.sidecar'),
            file_get_contents(self::TEST_FILES_FOLDER.'video.sidecar')
        );
    }

    public function testSideCarWithDocument()
    {
        //act
        $this->encryption->encryptFile(
            self::SAMPLES_FILES_FOLDER.'IMAGE.jpeg',
            self::SAMPLES_FILES_FOLDER.'IMAGE.key'
        );

        $sideCar = $this->encryption->getSideCar();

        file_put_contents(self::TEST_FILES_FOLDER.'video.sidecar', $sideCar);

        //assert
        $this->assertEquals(null, $sideCar);
    }
}
