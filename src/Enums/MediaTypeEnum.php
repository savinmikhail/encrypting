<?php

namespace Mikhail\Encryptor\Enums;

enum MediaTypeEnum: string
{
    case IMAGE = 'WhatsApp Image Keys';
    case VIDEO = 'WhatsApp Video Keys';
    case AUDIO = 'WhatsApp Audio Keys';
    case DOCUMENT = 'WhatsApp Document Keys';
}
