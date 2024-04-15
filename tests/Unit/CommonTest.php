<?php

namespace Tests\Unit;

use PHPUnit\Framework\TestCase;
use src\Decryption;
use src\Encryption;
use src\Exceptions\CorruptedMediaKeyException;
use src\Exceptions\CryptException;
use src\Exceptions\EmptyFileException;
use src\Exceptions\FileNotFoundException;

class CommonTest extends TestCase
{
    private const /*string*/ TEST_FILES_FOLDER = 'tests/Unit/testFiles/';

    private Decryption $decryption;

    private Encryption $encryption;

    public function setUp(): void
    {
        $this->decryption = new Decryption();
        $this->encryption = new Encryption();
    }

    public function testEncryptionDecryptionWithInvalidFilePath()
    {
        $this->expectException(FileNotFoundException::class);
        $this->encryption->encryptFile('path/to/invalid_file.txt');
    }

    public function testEncryptionDecryptionWithEmptyFile()
    {
        $this->expectException(EmptyFileException::class);
        $this->encryption->encryptFile(self::TEST_FILES_FOLDER.'empty_file.txt');
    }

    public function testEncryptionDecryptionWithInvalidKeyFile()
    {
        $this->expectException(FileNotFoundException::class);
        $this->encryption->encryptFile(
            self::TEST_FILES_FOLDER.'orig.txt',
            'path/to/invalid_key.txt'
        );
    }

    public function testEncryptionDecryptionWithCorruptedEncryptedFile()
    {
        $this->expectException(CryptException::class);
        $this->decryption->decryptFile(self::TEST_FILES_FOLDER.'corrupted_enc.txt');
    }

    public function testEncryptionDecryptionWithIncorrectMediaKey()
    {
        $this->expectException(CorruptedMediaKeyException::class);
        $this->decryption->decryptFile(
            self::TEST_FILES_FOLDER.'enc.txt',
            self::TEST_FILES_FOLDER.'incorrect_media_key.txt'
        );
    }

    public function testEncryptionDecryptionWithStringData()
    {
        $encryptedString = $this->encryption->encryptFile(self::TEST_FILES_FOLDER.'orig.txt');
        file_put_contents(self::TEST_FILES_FOLDER.'enc.txt', $encryptedString);

        $decryptedString = $this->decryption->decryptFile(self::TEST_FILES_FOLDER.'enc.txt');
        file_put_contents(self::TEST_FILES_FOLDER.'dec.txt', $decryptedString);

        $this->assertEquals(
            file_get_contents(self::TEST_FILES_FOLDER.'orig.txt'),
            file_get_contents(self::TEST_FILES_FOLDER.'dec.txt')
        );
    }

    public function testEncryptionDecryptionWithCustomImage()
    {
        $encryptedString = $this->encryption->encryptFile(self::TEST_FILES_FOLDER.'myImage.png');
        file_put_contents(self::TEST_FILES_FOLDER.'myImageEnc.png', $encryptedString);

        $decryptedString = $this->decryption->decryptFile(self::TEST_FILES_FOLDER.'myImageEnc.png');
        file_put_contents(self::TEST_FILES_FOLDER.'myImageDec.png', $decryptedString);

        $originalHash = hash_file('sha256', self::TEST_FILES_FOLDER.'myImage.png');
        $decryptedHash = hash_file('sha256', self::TEST_FILES_FOLDER.'myImageDec.png');

        $this->assertEquals($originalHash, $decryptedHash);
    }
}
