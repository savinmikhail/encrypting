<?php

namespace Tests\Unit;

use GuzzleHttp\Psr7\Stream;
use Psr\Http\Message\StreamInterface;
use src\Exceptions\EmptyFileException;
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

    protected function getStreamFromFile(string $filePath): StreamInterface
    {
        if (! file_exists($filePath)) {
            throw new FileNotFoundException("File $filePath does not exist");
        }
        // Check if the file is empty
        if (filesize($filePath) === 0) {
            throw new EmptyFileException("File $filePath is empty");
        }
        $stream = fopen($filePath, 'r');
        fseek($stream, 0);

        return new Stream($stream);
    }
}
