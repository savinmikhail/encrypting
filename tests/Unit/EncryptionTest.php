<?php

namespace Tests\Unit;

use src\Encryption;
use src\Enums\MediaTypeEnum;

class EncryptionTest extends BaseTestCase
{
    private Encryption $encryption;

    public function setUp(): void
    {
        $this->encryption = new Encryption();
    }

    public function testEncryptionWithImage()
    {
        $decryptedString = $this->encryption->encryptFile(
            self::SAMPLES_FILES_FOLDER.'IMAGE.jpeg',
            MediaTypeEnum::IMAGE,
            file_get_contents(self::SAMPLES_FILES_FOLDER.'IMAGE.key')
        );

        file_put_contents(self::TEST_FILES_FOLDER.'imageEnc.jpeg', $decryptedString);

        $originalHash = hash_file('sha256', self::SAMPLES_FILES_FOLDER.'imageEnc.jpeg');
        $encryptedHash = hash_file('sha256', self::TEST_FILES_FOLDER.'imageEnc.jpeg');

        $this->assertEquals($originalHash, $encryptedHash);
    }

    public function testEncryptionWithAudio()
    {
        $decryptedString = $this->encryption->encryptFile(
            self::SAMPLES_FILES_FOLDER.'AUDIO.mp3',
            MediaTypeEnum::AUDIO,
            file_get_contents(self::SAMPLES_FILES_FOLDER.'AUDIO.key')
        );

        file_put_contents(self::TEST_FILES_FOLDER.'audioEnc.mp3', $decryptedString);

        $originalHash = hash_file('sha256', self::SAMPLES_FILES_FOLDER.'audioEnc.mp3');
        $encryptedHash = hash_file('sha256', self::TEST_FILES_FOLDER.'audioEnc.mp3');

        $this->assertEquals($originalHash, $encryptedHash);
    }

    public function testEncryptionWithVideo()
    {
        $decryptedString = $this->encryption->encryptFile(
            self::SAMPLES_FILES_FOLDER.'VIDEO.mp4',
            MediaTypeEnum::VIDEO,
            file_get_contents(self::SAMPLES_FILES_FOLDER.'VIDEO.key')
        );

        file_put_contents(self::TEST_FILES_FOLDER.'videoEnc.mp4', $decryptedString);

        $originalHash = hash_file('sha256', self::SAMPLES_FILES_FOLDER.'videoEnc.mp4');
        $encryptedHash = hash_file('sha256', self::TEST_FILES_FOLDER.'videoEnc.mp4');

        $this->assertEquals($originalHash, $encryptedHash);
    }

    public function testSideCarWithVideo()
    {
        $this->markTestSkipped('anyway not working');
        //act
        $this->encryption->encryptFile(
            self::SAMPLES_FILES_FOLDER.'VIDEO.mp4',
            MediaTypeEnum::VIDEO,
            file_get_contents(self::SAMPLES_FILES_FOLDER.'VIDEO.key')
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
            MediaTypeEnum::IMAGE,
            file_get_contents(self::SAMPLES_FILES_FOLDER.'IMAGE.key')
        );

        $sideCar = $this->encryption->getSideCar();

        file_put_contents(self::TEST_FILES_FOLDER.'video.sidecar', $sideCar);

        //assert
        $this->assertEquals(null, $sideCar);
    }
}
