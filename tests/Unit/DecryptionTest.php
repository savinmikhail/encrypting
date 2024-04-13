<?php

namespace Tests\Unit;

use PHPUnit\Framework\TestCase;
use src\Encryption;
use src\Exceptions\CorruptedMediaKeyException;
use src\Exceptions\CryptException;
use src\Exceptions\EmptyFileException;
use src\Exceptions\FileNotFoundException;

class DecryptionTest extends TestCase
{
    private const /*string*/ TEST_FILES_FOLDER = 'tests/Unit/testFiles/';

    private const /*string*/ SAMPLES_FILES_FOLDER = 'samples/';

    public function testDecryptionWithAudio()
    {
        $encryptor = new Encryption();
        // Decrypt the encrypted stream data
        $decryptedString = $encryptor->decryptFile(
            self::SAMPLES_FILES_FOLDER.'audioEnc.mp3',
            self::SAMPLES_FILES_FOLDER.'AUDIO.key'
        );

        file_put_contents(self::TEST_FILES_FOLDER.'AUDIO.mp3', $decryptedString);

        // Calculate hashes of the original and decrypted files
        $originalHash = hash_file('sha256', self::SAMPLES_FILES_FOLDER.'AUDIO.mp3');
        $decryptedHash = hash_file('sha256', self::TEST_FILES_FOLDER.'AUDIO.mp3');
        $this->assertEquals($originalHash, $decryptedHash);
        // Assert that the decrypted string matches the original input string
        //        $this->assertEquals(file_get_contents('samples/AUDIO.mp3'), file_get_contents('AUDIO.mp3'));
    }
    public function testDecryptionWithVideo()
    {
        $encryptor = new Encryption();
        // Decrypt the encrypted stream data
        $decryptedString = $encryptor->decryptFile(
            self::SAMPLES_FILES_FOLDER.'videoEnc.mp4',
            self::SAMPLES_FILES_FOLDER.'VIDEO.key'
        );

        file_put_contents(self::TEST_FILES_FOLDER.'VIDEO.mp4', $decryptedString);

        // Calculate hashes of the original and decrypted files
        $originalHash = hash_file('sha256', self::SAMPLES_FILES_FOLDER.'VIDEO.mp4');
        $decryptedHash = hash_file('sha256', self::TEST_FILES_FOLDER.'VIDEO.mp4');
        $this->assertEquals($originalHash, $decryptedHash);
        // Assert that the decrypted string matches the original input string
        //        $this->assertEquals(file_get_contents('samples/AUDIO.mp3'), file_get_contents('AUDIO.mp3'));
    }

    public function testDecryptionWithImageFromSamples()
    {
        $encryptor = new Encryption();
        // Decrypt the encrypted stream data
        $decryptedString = $encryptor->decryptFile(
            self::SAMPLES_FILES_FOLDER.'imageEnc.jpeg',
            self::SAMPLES_FILES_FOLDER.'IMAGE.key'
        );

        file_put_contents(self::TEST_FILES_FOLDER.'IMAGE.jpeg', $decryptedString);
        // Assert that the decrypted string matches the original input string
        $this->assertEquals(
            file_get_contents(self::SAMPLES_FILES_FOLDER.'IMAGE.jpeg'),
            file_get_contents(self::TEST_FILES_FOLDER.'IMAGE.jpeg')
        );
    }
}
