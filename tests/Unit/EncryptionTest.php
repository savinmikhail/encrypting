<?php

namespace Tests\Unit;

use PHPUnit\Framework\TestCase;
use src\Decryption;
use src\Encryption;
use src\Exceptions\CorruptedMediaKeyException;
use src\Exceptions\CryptException;
use src\Exceptions\EmptyFileException;
use src\Exceptions\FileNotFoundException;

class EncryptionTest extends TestCase
{
    private const /*string*/ TEST_FILES_FOLDER = 'tests/Unit/testFiles/';

    private const /*string*/ SAMPLES_FILES_FOLDER = 'samples/';

    private Encryption $encryption;
    private Decryption $decryption;

    public function setUp(): void
    {
        $this->encryption = new Encryption();
        $this->decryption = new Decryption();
    }

    public function testEncryptionDecryptionWithStringData()
    {
        //act
        $encryptedString = $this->encryption->encryptFile(self::TEST_FILES_FOLDER.'orig.txt');
        $decryptedString = $this->decryption->decryptFile(self::TEST_FILES_FOLDER.'enc.txt');

        file_put_contents(self::TEST_FILES_FOLDER.'enc.txt', $encryptedString);
        file_put_contents(self::TEST_FILES_FOLDER.'dec.txt', $decryptedString);

        //assert
        $this->assertEquals(
            file_get_contents(self::TEST_FILES_FOLDER.'orig.txt'),
            file_get_contents(self::TEST_FILES_FOLDER.'dec.txt')
        );
    }

    public function testEncryptionDecryptionWithInvalidFilePath()
    {
        //assert
        $this->expectException(FileNotFoundException::class);
        //act
        $this->encryption->encryptFile('path/to/invalid_file.txt');
    }

    public function testEncryptionDecryptionWithEmptyFile()
    {
        //assert
        $this->expectException(EmptyFileException::class);
        //act
        $this->encryption->encryptFile(self::TEST_FILES_FOLDER.'empty_file.txt');
    }

    public function testEncryptionDecryptionWithInvalidKeyFile()
    {
        //assert
        $this->expectException(FileNotFoundException::class);
        //act
        $this->encryption->encryptFile(
            self::TEST_FILES_FOLDER.'orig.txt',
            'path/to/invalid_key.txt'
        );
    }

    public function testEncryptionDecryptionWithCorruptedEncryptedFile()
    {
        //assert
        $this->expectException(CryptException::class);
        //act
        $this->decryption->decryptFile(self::TEST_FILES_FOLDER.'corrupted_enc.txt');
    }

    public function testEncryptionDecryptionWithIncorrectMediaKey()
    {
        //assert
        $this->expectException(CorruptedMediaKeyException::class);
        //act
        $this->decryption->decryptFile(
            self::TEST_FILES_FOLDER.'enc.txt',
            self::TEST_FILES_FOLDER.'incorrect_media_key.txt'
        );
    }

    public function testEncryptionDecryptionWithCustomImage()
    {
        //act
        $encryptedString = $this->encryption->encryptFile(self::TEST_FILES_FOLDER.'myImage.png');
        $decryptedString = $this->decryption->decryptFile(self::TEST_FILES_FOLDER.'myImageEnc.png');

        file_put_contents(self::TEST_FILES_FOLDER.'myImageEnc.png', $encryptedString);
        file_put_contents(self::TEST_FILES_FOLDER.'myImageDec.png', $decryptedString);

        $originalHash = hash_file('sha256', self::TEST_FILES_FOLDER.'myImage.png');
        $decryptedHash = hash_file('sha256', self::TEST_FILES_FOLDER.'myImageDec.png');

        //assert
        $this->assertEquals($originalHash, $decryptedHash);
    }

    public function testDecryptionWithImageFromSamples()
    {
        //act
        $decryptedString = $this->decryption->decryptFile(
            self::SAMPLES_FILES_FOLDER.'imageEnc.jpeg',
            self::SAMPLES_FILES_FOLDER.'IMAGE.key'
        );

        file_put_contents(self::TEST_FILES_FOLDER.'IMAGE.jpeg', $decryptedString);

        $originalHash = hash_file('sha256', self::SAMPLES_FILES_FOLDER.'IMAGE.jpeg');
        $decryptedHash = hash_file('sha256', self::TEST_FILES_FOLDER.'IMAGE.jpeg');

        //assert
        $this->assertEquals(
            $originalHash,
            $decryptedHash,
        );
    }

    public function testEncryptionWithImage()
    {
        //act
        $decryptedString = $this->encryption->encryptFile(
            self::SAMPLES_FILES_FOLDER.'IMAGE.jpeg',
            self::SAMPLES_FILES_FOLDER.'IMAGE.key'
        );

        file_put_contents(self::TEST_FILES_FOLDER.'imageEnc.jpeg', $decryptedString);

        $originalHash = hash_file('sha256', self::SAMPLES_FILES_FOLDER.'imageEnc.jpeg');
        $encryptedHash = hash_file('sha256', self::TEST_FILES_FOLDER.'imageEnc.jpeg');

        //assert
        $this->assertEquals($originalHash, $encryptedHash);
    }

    public function testDecryptionWithAudio()
    {
        //act
        $decryptedString = $this->decryption->decryptFile(
            self::SAMPLES_FILES_FOLDER.'audioEnc.mp3',
            self::SAMPLES_FILES_FOLDER.'AUDIO.key'
        );

        file_put_contents(self::TEST_FILES_FOLDER.'AUDIO.mp3', $decryptedString);

        $originalHash = hash_file('sha256', self::SAMPLES_FILES_FOLDER.'AUDIO.mp3');
        $decryptedHash = hash_file('sha256', self::TEST_FILES_FOLDER.'AUDIO.mp3');

        //assert
        $this->assertEquals($originalHash, $decryptedHash);
    }

    public function testEncryptionWithAudio()
    {
        //act
        $decryptedString = $this->encryption->encryptFile(
            self::SAMPLES_FILES_FOLDER.'AUDIO.mp3',
            self::SAMPLES_FILES_FOLDER.'AUDIO.key'
        );

        file_put_contents(self::TEST_FILES_FOLDER.'audioEnc.mp3', $decryptedString);

        $originalHash = hash_file('sha256', self::SAMPLES_FILES_FOLDER.'audioEnc.mp3');
        $encryptedHash = hash_file('sha256', self::TEST_FILES_FOLDER.'audioEnc.mp3');

        //assert
        $this->assertEquals($originalHash, $encryptedHash);
    }

    public function testDecryptionWithVideo()
    {
        //act
        $decryptedString = $this->decryption->decryptFile(
            self::SAMPLES_FILES_FOLDER.'videoEnc.mp4',
            self::SAMPLES_FILES_FOLDER.'VIDEO.key'
        );

        file_put_contents(self::TEST_FILES_FOLDER.'VIDEO.mp4', $decryptedString);

        $originalHash = hash_file('sha256', self::SAMPLES_FILES_FOLDER.'VIDEO.mp4');
        $decryptedHash = hash_file('sha256', self::TEST_FILES_FOLDER.'VIDEO.mp4');

        //assert
        $this->assertEquals($originalHash, $decryptedHash);
    }

    public function testEncryptionWithVideo()
    {
       //act
        $encryptedString = $this->encryption->encryptFile(
            self::SAMPLES_FILES_FOLDER.'VIDEO.mp4',
            self::SAMPLES_FILES_FOLDER.'VIDEO.key'
        );

        file_put_contents(self::TEST_FILES_FOLDER.'videoEnc.mp4', $encryptedString);

        $originalHash = hash_file('sha256', self::SAMPLES_FILES_FOLDER.'videoEnc.mp4');
        $encryptedHash = hash_file('sha256', self::TEST_FILES_FOLDER.'videoEnc.mp4');

       //assert
        $this->assertEquals($originalHash, $encryptedHash);
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
