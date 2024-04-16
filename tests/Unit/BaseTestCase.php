<?php

namespace Tests\Unit;

use src\Exceptions\FileNotFoundException;
use Tests\TestCase;

class BaseTestCase extends TestCase
{
    protected const /*string*/ TEST_FILES_FOLDER = 'tests/Unit/testFiles/';

    protected const /*string*/ SAMPLES_FILES_FOLDER = 'samples/';

    protected function getMediaKeyFromFile(string $keyFileName): string
    {
        if (! file_exists($keyFileName)) {
            throw new FileNotFoundException('mediaKey not found');
        }

        // Obtain mediaKey (your implementation to obtain the media key)
        return file_get_contents($keyFileName);
    }
}
