<?php

namespace Tests\Unit;

use PHPUnit\Framework\TestCase;
use src\Encryption;
use src\Exceptions\CorruptedMediaKeyException;
use src\Exceptions\CryptException;
use src\Exceptions\EmptyFileException;
use src\Exceptions\FileNotFoundException;

class EncryptionTest extends TestCase
{
    private const /*string*/ TEST_FILES_FOLDER = 'tests/Unit/testFiles/';

    private const /*string*/ SAMPLES_FILES_FOLDER = 'samples/';

    public function testEncryptionDecryptionWithStringData()
    {
        $encryptor = new Encryption();

        // Encrypt the stream data
        $encryptedString = $encryptor->encryptFile(self::TEST_FILES_FOLDER.'orig.txt');

        file_put_contents(self::TEST_FILES_FOLDER.'enc.txt', $encryptedString);

        // Decrypt the encrypted stream data
        $decryptedString = $encryptor->decryptFile(self::TEST_FILES_FOLDER.'enc.txt');

        file_put_contents(self::TEST_FILES_FOLDER.'dec.txt', $decryptedString);
        // Assert that the decrypted string matches the original input string
        $this->assertEquals(
            file_get_contents(self::TEST_FILES_FOLDER.'orig.txt'),
            file_get_contents(self::TEST_FILES_FOLDER.'dec.txt')
        );
    }

    public function testEncryptionDecryptionWithInvalidFilePath()
    {
        // Test encryption and decryption with invalid file paths
        $encryptor = new Encryption();
        $this->expectException(FileNotFoundException::class);
        $encryptor->encryptFile('path/to/invalid_file.txt');
    }

    public function testEncryptionDecryptionWithEmptyFile()
    {
        // Test encryption and decryption with an empty file
        $encryptor = new Encryption();
        $this->expectException(EmptyFileException::class);
        $encryptor->encryptFile(self::TEST_FILES_FOLDER.'empty_file.txt');
    }

    public function testEncryptionDecryptionWithInvalidKeyFile()
    {
        // Test encryption and decryption with an invalid key file
        $encryptor = new Encryption();
        $this->expectException(FileNotFoundException::class);
        $encryptor->encryptFile(
            self::TEST_FILES_FOLDER.'orig.txt',
            'path/to/invalid_key.txt'
        );
    }

    public function testEncryptionDecryptionWithCorruptedEncryptedFile()
    {
        // Test decryption with a corrupted encrypted file
        $encryptor = new Encryption();
        $this->expectException(CryptException::class);
        $encryptor->decryptFile(self::TEST_FILES_FOLDER.'corrupted_enc.txt');
    }

    public function testEncryptionDecryptionWithIncorrectMediaKey()
    {
        // Test decryption with an incorrect media key
        $encryptor = new Encryption();
        $this->expectException(CorruptedMediaKeyException::class);
        $encryptor->decryptFile(
            self::TEST_FILES_FOLDER.'enc.txt',
            self::TEST_FILES_FOLDER.'incorrect_media_key.txt'
        );
    }

    public function testEncryptionDecryptionWithCustomImage()
    {
        $encryptor = new Encryption();
        $encryptedString = $encryptor->encryptFile(self::TEST_FILES_FOLDER.'myImage.png');
        file_put_contents(self::TEST_FILES_FOLDER.'myImageEnc.png', $encryptedString);
        $decryptedString = $encryptor->decryptFile(self::TEST_FILES_FOLDER.'myImageEnc.png');
        file_put_contents(self::TEST_FILES_FOLDER.'myImageDec.png', $decryptedString);

        // Calculate hashes of the original and decrypted files
        $originalHash = hash_file('sha256', self::TEST_FILES_FOLDER.'myImage.png');
        $decryptedHash = hash_file('sha256', self::TEST_FILES_FOLDER.'myImageDec.png');
        $this->assertEquals($originalHash, $decryptedHash);
        //        $this->assertEquals(file_get_contents('myImage.png'), file_get_contents('decMyImage.png'));
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
}
