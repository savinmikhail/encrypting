<?php

namespace Mikhail\Tests\Encryptor;

use Mikhail\Encryptor\Decryption;
use Mikhail\Encryptor\Encryption;
use Mikhail\Encryptor\Enums\MediaTypeEnum;
use Mikhail\Encryptor\Exceptions\CorruptedMediaKeyException;
use Mikhail\Encryptor\Exceptions\CryptException;

class CommonTest extends BaseTestCase
{
    private Decryption $decryption;

    private Encryption $encryption;

    public function setUp(): void
    {
        $this->decryption = new Decryption();
        $this->encryption = new Encryption();
    }

    public function testEncryptionDecryptionWithCorruptedEncryptedFile()
    {
        $this->expectException(CryptException::class);
        $this->decryption->decryptStream(
            $this->getStreamFromFile(self::TEST_FILES_FOLDER.'corrupted_enc.txt'),
            file_get_contents('mediaKey.txt'),
            MediaTypeEnum::DOCUMENT,
        );
    }

    public function testEncryptionDecryptionWithIncorrectMediaKey()
    {
        $this->expectException(CorruptedMediaKeyException::class);
        $this->decryption->decryptStream(
            $this->getStreamFromFile(self::TEST_FILES_FOLDER.'enc.txt'),
            file_get_contents(self::TEST_FILES_FOLDER.'incorrect_media_key.txt'),
            MediaTypeEnum::DOCUMENT,
        );
    }

    public function testEncryptionDecryptionWithStringData()
    {
        $encryptedString = $this->encryption->encryptStream(
            $this->getStreamFromFile(self::TEST_FILES_FOLDER.'orig.txt'),
            MediaTypeEnum::DOCUMENT,
        );
        file_put_contents(self::TEST_FILES_FOLDER.'enc.txt', $encryptedString);

        $decryptedString = $this->decryption->decryptStream(
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
        $encryptedString = $this->encryption->encryptStream(
            $this->getStreamFromFile(self::TEST_FILES_FOLDER.'myImage.png'),
            MediaTypeEnum::IMAGE,
        );
        file_put_contents(self::TEST_FILES_FOLDER.'myImageEnc.png', $encryptedString);

        $decryptedString = $this->decryption->decryptStream(
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
