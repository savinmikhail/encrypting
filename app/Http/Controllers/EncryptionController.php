<?php

namespace App\Http\Controllers;

use GuzzleHttp\Psr7\ServerRequest;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Crypt;
use Psr\Http\Message\StreamInterface;

class EncryptionController extends Controller
{
    public function encryptText(Request $request)
    {
        // Получаем текст для шифрования из запроса
        $text = $request->input('text');

        // Шифруем текст
        $encryptedText = Crypt::encryptString($text);

        // Возвращаем зашифрованный текст
        return response()->json(['encrypted_text' => $encryptedText]);
    }

    public function decryptText(Request $request)
    {
        // Получаем зашифрованный текст из запроса
        $encryptedText = $request->input('encrypted_text');

        // Расшифровываем текст
        $decryptedText = Crypt::decryptString($encryptedText);

        // Возвращаем расшифрованный текст
        return response()->json(['decrypted_text' => $decryptedText]);
    }

    public function encryptStream()
    {
        // Create a PSR-7 ServerRequest instance
        $psr7Request = ServerRequest::fromGlobals();

        // Get the PSR-7 stream from the request
        $stream = $psr7Request->getBody();

        // Encrypt the stream data one by one
        $encryptedStream = $this->encryptStreamData($stream);

        // Return the encrypted stream
        return response()->stream(function () use ($encryptedStream) {
            echo $encryptedStream;
        });
    }

    public function decryptStream()
    {
        // Create a PSR-7 ServerRequest instance
        $psr7Request = ServerRequest::fromGlobals();

        // Get the PSR-7 stream from the request
        $stream = $psr7Request->getBody();

        // Decrypt the stream data one by one
        $decryptedStream = $this->decryptStreamData($stream);

        // Return the decrypted stream
        return response()->stream(function () use ($decryptedStream) {
            echo $decryptedStream;
        });
    }

    private function decryptStreamData(StreamInterface $stream)
    {
        // Obtain mediaKey (your implementation to obtain the media key)
        $mediaKey = '...'; // Replace with your code to obtain the media key

        // Expand mediaKey to 112 bytes using HKDF with SHA-256 and type-specific application info
        $mediaKeyExpanded = $this->expandMediaKey($mediaKey);

        // Split mediaKeyExpanded into iv, cipherKey, and macKey
        $iv = substr($mediaKeyExpanded, 0, 16);
        $cipherKey = substr($mediaKeyExpanded, 16, 32);
        $macKey = substr($mediaKeyExpanded, 48, 32);

        // Read the stream and split the encrypted media data and MAC
        $mediaData = (string) $stream;
        $encryptedFile = substr($mediaData, 0, -10);
        $mac = substr($mediaData, -10);

        // Validate media data with HMAC by signing iv + encryptedFile with macKey using SHA-256
        $computedMac = hash_hmac('sha256', $iv . $encryptedFile, $macKey, true);
        $computedMac = substr($computedMac, 0, 10);

        // Compare the computed MAC with the received MAC
        if (!hash_equals($mac, $computedMac)) {
            throw new \Exception('MAC validation failed');
        }

        // Decrypt the file with AES-CBC using cipherKey and iv
        $decryptedFile = openssl_decrypt($encryptedFile, 'aes-256-cbc', $cipherKey, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $iv);

        // Unpad the decrypted file
        $decryptedFile = $this->unpad($decryptedFile);

        return $decryptedFile;
    }

    private function expandMediaKey($mediaKey) {
        // Expand the media key using HKDF with SHA-256
        $mediaKeyExpanded = hash_hkdf('sha256', $mediaKey, 112, 'mediaKeyExpansion', '');

        // Split the expanded key into iv, cipherKey, macKey, and refKey
        $iv = substr($mediaKeyExpanded, 0, 16);
        $cipherKey = substr($mediaKeyExpanded, 16, 32);
        $macKey = substr($mediaKeyExpanded, 48, 32);

        // Concatenate iv, cipherKey, and macKey into a single string
        $expandedKey = $iv . $cipherKey . $macKey;

        // Return the concatenated string
        return $expandedKey;
    }


    private function unpad($data)
    {
        $padding = ord($data[strlen($data) - 1]);
        return substr($data, 0, -$padding);
    }

    /**
     * @throws RandomException
     */
    private function encryptStreamData(StreamInterface $stream)
    {
        // Generate a mediaKey (32 bytes)
        $mediaKey = random_bytes(32);

        // Expand the mediaKey to 112 bytes using HKDF
        $mediaKeyExpanded = hash_hkdf('sha256', $mediaKey, 112, 'application-specific-info');

        // Split mediaKeyExpanded into iv, cipherKey, macKey
        $iv = substr($mediaKeyExpanded, 0, 16);
        $cipherKey = substr($mediaKeyExpanded, 16, 32);
        $macKey = substr($mediaKeyExpanded, 48, 32);

        // Initialize OpenSSL encryption cipher
        $cipher = 'aes-256-cbc';

        // Initialize the encryption buffer
        $encryptedData = '';

        // Encrypt the stream data chunk by chunk
        while (!$stream->eof()) {
            // Read a chunk of data from the stream
            $chunk = $stream->read(1024);

            // Encrypt the chunk of data
            $encryptedChunk = openssl_encrypt($chunk, $cipher, $cipherKey, OPENSSL_RAW_DATA, $iv);

            // Append the encrypted chunk to the encrypted data
            $encryptedData .= $encryptedChunk;
        }

        // Calculate HMAC for iv + encrypted data using macKey
        $mac = hash_hmac('sha256', $iv . $encryptedData, $macKey, true);

        // Take the first 10 bytes of the HMAC as the MAC
        $mac = substr($mac, 0, 10);

        // Append the MAC to the encrypted data
        $encryptedStream = $encryptedData . $mac;

        return $encryptedStream;
    }
}
