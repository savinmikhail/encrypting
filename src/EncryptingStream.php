<?php

namespace src;

use GuzzleHttp\Psr7\StreamDecoratorTrait;
use Psr\Http\Message\StreamInterface;

class EncryptingStream implements StreamInterface
{
    use StreamDecoratorTrait;
}
