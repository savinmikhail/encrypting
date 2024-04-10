<?php

namespace Tests\Unit;

use App\Services\Encryption;
use PHPUnit\Framework\TestCase;

class EncryptionTest extends TestCase
{
    public function testEncryptionDecryptionWithStringData()
    {
        $encryptor = new Encryption();

        // Encrypt the stream data
        $encryptedString = $encryptor->encryptFile('orig.txt');

        file_put_contents('enc.txt', $encryptedString);

        // Decrypt the encrypted stream data
        $decryptedString = $encryptor->decryptFile('enc.txt');

        // Assert that the decrypted string matches the original input string
        $this->assertEquals(file_get_contents('orig.txt'), $decryptedString);
    }
}
