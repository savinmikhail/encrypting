# Crypt


See the task below


# Тестовое задание для PHP-разработчика

Требуется реализовать декораторы для [PSR-7 потоков](https://github.com/php-fig/http-message/blob/14b9b813c5e36af4498ef38ef97938bf7090fd52/src/StreamInterface.php), которые будут зашифровывать и расшифровывать их по алгоритмам, используемым WhatsApp.
Текстовые описания алгоритмов можно будет найти ниже.

Код необходимо оформить в виде пакета для composer. От реализации ожидается промышленное качество кода.

Тестовые файлы можно найти в папке `samples`:

* `*.original` - оригинальный файл;
* `*.key` - ключ для шифрования (дешифрования) - `mediaKey`;
* `*.encrypted` - зашифрованный файл;
* `*.sidecar` - информация для стриминга.

В качестве задания со звёздочкой можно реализовать генерацию информации для стриминга.
Эта генерация не должна делать дополнительных чтений из потока-исходника.

## Шифрование

1. Generate your own `mediaKey`, which needs to be 32 bytes, or use an existing one when available.
2. Expand it to 112 bytes using HKDF with SHA-256 and type-specific application info (see below). Call this value `mediaKeyExpanded`.
3. Split `mediaKeyExpanded` into:
    - `iv`: `mediaKeyExpanded[:16]`
    - `cipherKey`: `mediaKeyExpanded[16:48]`
    - `macKey`: `mediaKeyExpanded[48:80]`
    - `refKey`: `mediaKeyExpanded[80:]` (not used)
4. Encrypt the file with AES-CBC using `cipherKey` and `iv`, pad it and call it `enc`.
5. Sign `iv + enc` with `macKey` using HMAC SHA-256 and store the first 10 bytes of the hash as `mac`.
   to obtain the result.

## Дешифрование

1. Obtain `mediaKey`.
2. Expand it to 112 bytes using HKDF with SHA-256 and type-specific application info (see below). Call this value `mediaKeyExpanded`.
3. Split `mediaKeyExpanded` into:
    - `iv`: `mediaKeyExpanded[:16]`
    - `cipherKey`: `mediaKeyExpanded[16:48]`
    - `macKey`: `mediaKeyExpanded[48:80]`
    - `refKey`: `mediaKeyExpanded[80:]` (not used)
4. Obtain encrypted media data and split it into:
    - `file`: `mediaData[:-10]`
    - `mac`: `mediaData[-10:]`
5. Validate media data with HMAC by signing `iv + file` with `macKey` using SHA-256. Take in mind that `mac` is truncated to 10 bytes, so you should compare only the first 10 bytes.
6. Decrypt `file` with AES-CBC using `cipherKey` and `iv`, and unpad it to obtain the result.

## Информационные строки для HKDF

HKDF позволяет указывать информационные строки, специфичные для контекста/приложения.
В данном случае контекстом является тип файла, для каждого из которых своя информационная строка:

| Media Type | Application Info         |
| ---------- | ------------------------ |
| IMAGE      | `WhatsApp Image Keys`    |
| VIDEO      | `WhatsApp Video Keys`    |
| AUDIO      | `WhatsApp Audio Keys`    |
| DOCUMENT   | `WhatsApp Document Keys` |

## Информация для стриминга

This step is required only for streamable media, e.g. video and audio.
As CBC mode allows to decrypt a data from random offset (block-size aligned), it is possible to play and seek the media without the need to fully download it.
That said, we have to generate a `sidecar`.

Do it by signing every `[n*64K, (n+1)*64K+16]` chunk with `macKey`, truncating the result to the first 10 bytes.
Then combine everything in one piece.

## Полезные пакеты

* [jsq/psr7-stream-encryption](https://github.com/jeskew/php-encrypted-streams) - декораторы для шифрования, дешифрования и хеширования;
* [guzzlehttp/psr7](https://github.com/guzzle/psr7) - одна из реализаций PSR-7.

