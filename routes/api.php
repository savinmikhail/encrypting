<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\EncryptionController;

Route::post('/encrypt', [EncryptionController::class, 'encryptText']);
Route::post('/decrypt', [EncryptionController::class, 'decryptText']);

Route::post('/stream/enc', [EncryptionController::class, 'encryptStream']);
Route::post('/stream/dec', [EncryptionController::class, 'decryptStream']);

