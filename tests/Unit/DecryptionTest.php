<?php

namespace Tests\Unit;

use src\Decryption;
use src\Enums\MediaTypeEnum;

class DecryptionTest extends BaseTestCase
{
    private Decryption $decryption;

    public function setUp(): void
    {
        $this->decryption = new Decryption();
    }

    public function testDecryptionWithAudio()
    {
        $decryptedString = $this->decryption->decryptStream(
            $this->getStreamFromFile(self::SAMPLES_FILES_FOLDER.'audioEnc.mp3'),
            file_get_contents(self::SAMPLES_FILES_FOLDER.'AUDIO.key'),
            MediaTypeEnum::AUDIO,
        );

        file_put_contents(self::TEST_FILES_FOLDER.'AUDIO.mp3', $decryptedString);

        $originalHash = hash_file('sha256', self::SAMPLES_FILES_FOLDER.'AUDIO.mp3');
        $decryptedHash = hash_file('sha256', self::TEST_FILES_FOLDER.'AUDIO.mp3');

        $this->assertEquals($originalHash, $decryptedHash);
    }

    public function testDecryptionWithVideo()
    {
        $decryptedString = $this->decryption->decryptStream(
            $this->getStreamFromFile(self::SAMPLES_FILES_FOLDER.'videoEnc.mp4'),
            file_get_contents(self::SAMPLES_FILES_FOLDER.'VIDEO.key'),
            MediaTypeEnum::VIDEO,
        );

        file_put_contents(self::TEST_FILES_FOLDER.'VIDEO.mp4', $decryptedString);

        $originalHash = hash_file('sha256', self::SAMPLES_FILES_FOLDER.'VIDEO.mp4');
        $decryptedHash = hash_file('sha256', self::TEST_FILES_FOLDER.'VIDEO.mp4');

        $this->assertEquals($originalHash, $decryptedHash);
    }

    public function testDecryptionWithImageFromSamples()
    {
        $decryptedString = $this->decryption->decryptStream(
            $this->getStreamFromFile(self::SAMPLES_FILES_FOLDER.'imageEnc.jpeg'),
            file_get_contents(self::SAMPLES_FILES_FOLDER.'IMAGE.key'),
            MediaTypeEnum::IMAGE,
        );

        file_put_contents(self::TEST_FILES_FOLDER.'IMAGE.jpeg', $decryptedString);

        $this->assertEquals(
            file_get_contents(self::SAMPLES_FILES_FOLDER.'IMAGE.jpeg'),
            file_get_contents(self::TEST_FILES_FOLDER.'IMAGE.jpeg')
        );
    }
}
