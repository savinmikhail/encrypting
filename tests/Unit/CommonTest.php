<?php

namespace Tests\Unit;

use src\Decryption;
use src\Encryption;
use src\Enums\MediaTypeEnum;
use src\Exceptions\CorruptedMediaKeyException;
use src\Exceptions\CryptException;
use src\Exceptions\EmptyFileException;
use src\Exceptions\FileNotFoundException;

class CommonTest extends BaseTestCase
{
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
        $this->encryption->encryptFile(
            $this->getStreamFromFile('path/to/invalid_file.txt'),
            MediaTypeEnum::DOCUMENT,
        );
    }

    public function testEncryptionDecryptionWithEmptyFile()
    {
        $this->expectException(EmptyFileException::class);
        $this->encryption->encryptFile(
            $this->getStreamFromFile(self::TEST_FILES_FOLDER.'empty_file.txt'),
            MediaTypeEnum::DOCUMENT,
        );
    }

    public function testEncryptionDecryptionWithCorruptedEncryptedFile()
    {
        $this->expectException(CryptException::class);
        $this->decryption->decryptFile(
            $this->getStreamFromFile(self::TEST_FILES_FOLDER.'corrupted_enc.txt'),
            file_get_contents('mediaKey.txt'),
            MediaTypeEnum::DOCUMENT,
        );
    }

    public function testEncryptionDecryptionWithIncorrectMediaKey()
    {
        $this->expectException(CorruptedMediaKeyException::class);
        $this->decryption->decryptFile(
            $this->getStreamFromFile( self::TEST_FILES_FOLDER.'enc.txt'),
            file_get_contents(self::TEST_FILES_FOLDER.'incorrect_media_key.txt'),
            MediaTypeEnum::DOCUMENT,
        );
    }

    public function testEncryptionDecryptionWithStringData()
    {
        $encryptedString = $this->encryption->encryptFile(
            $this->getStreamFromFile(self::TEST_FILES_FOLDER.'orig.txt'),
            MediaTypeEnum::DOCUMENT,
        );
        file_put_contents(self::TEST_FILES_FOLDER.'enc.txt', $encryptedString);

        $decryptedString = $this->decryption->decryptFile(
            $this->getStreamFromFile(self::TEST_FILES_FOLDER.'enc.txt'),
            file_get_contents('mediaKey.txt'),
            MediaTypeEnum::DOCUMENT,
        );
        file_put_contents(self::TEST_FILES_FOLDER.'dec.txt', $decryptedString);

        $this->assertEquals(
            file_get_contents(self::TEST_FILES_FOLDER.'orig.txt'),
            file_get_contents(self::TEST_FILES_FOLDER.'dec.txt')
        );
    }

    public function testEncryptionDecryptionWithCustomImage()
    {
        $encryptedString = $this->encryption->encryptFile(
            $this->getStreamFromFile(self::TEST_FILES_FOLDER.'myImage.png'),
            MediaTypeEnum::IMAGE,
        );
        file_put_contents(self::TEST_FILES_FOLDER.'myImageEnc.png', $encryptedString);

        $decryptedString = $this->decryption->decryptFile(
            $this->getStreamFromFile(self::TEST_FILES_FOLDER.'myImageEnc.png'),
            file_get_contents('mediaKey.txt'),
            MediaTypeEnum::IMAGE,
        );
        file_put_contents(self::TEST_FILES_FOLDER.'myImageDec.png', $decryptedString);

        $originalHash = hash_file('sha256', self::TEST_FILES_FOLDER.'myImage.png');
        $decryptedHash = hash_file('sha256', self::TEST_FILES_FOLDER.'myImageDec.png');

        $this->assertEquals($originalHash, $decryptedHash);
    }
}
