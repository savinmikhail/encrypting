<?php

namespace Tests\Unit;

use PHPUnit\Framework\TestCase;
use src\CorruptedMediaKeyException;
use src\CryptException;
use src\EmptyFileException;
use src\Encryption;
use src\FileNotFoundException;

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

        file_put_contents('dec.txt', $decryptedString);
        // Assert that the decrypted string matches the original input string
        $this->assertEquals(file_get_contents('orig.txt'), file_get_contents('dec.txt'));
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
        $encryptor->encryptFile('tests/Unit/samples/empty_file.txt');
    }

    public function testEncryptionDecryptionWithInvalidKeyFile()
    {
        // Test encryption and decryption with an invalid key file
        $encryptor = new Encryption();
        $this->expectException(FileNotFoundException::class);
        $encryptor->encryptFile('orig.txt', 'path/to/invalid_key.txt');
    }

    public function testEncryptionDecryptionWithCorruptedEncryptedFile()
    {
        // Test decryption with a corrupted encrypted file
        $encryptor = new Encryption();
        $this->expectException(CryptException::class);
        $encryptor->decryptFile('tests/Unit/samples/corrupted_enc.txt');
    }

    public function testEncryptionDecryptionWithIncorrectMediaKey()
    {
        // Test decryption with an incorrect media key
        $encryptor = new Encryption();
        $this->expectException(CorruptedMediaKeyException::class);
        $encryptor->decryptFile('enc.txt', 'tests/Unit/samples/incorrect_media_key.txt');
    }
}
