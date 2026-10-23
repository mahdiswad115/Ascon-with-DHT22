# Ascon with DHT22 on ESP32

Reads temperature and humidity from a DHT22 sensor on an ESP32, encrypts each
reading with Ascon, and sends it to a Python script that decrypts it.

## How it works

1. The ESP32 reads the DHT22 sensor (`dht22_integrate.ino`).
2. It encrypts the reading with Ascon authenticated encryption.
3. It sends the ciphertext over [Wi-Fi / serial / MQTT].
4. `receiver.py` decrypts and prints the reading.

## My work and third-party code

- **My work:** `dht22_integrate.ino`, `receiver.py`, [anything else]
- **Third-party code:** the Ascon C files (`aead.c`, `ascon.h`, `permutations.h`,
  `round.h` and related headers) come from [SOURCE URL] under the [LICENSE NAME]
  license. The original license text is in `LICENSE-ascon`.

## Hardware

- ESP32 [model]
- DHT22 sensor on pin [number]
- Wiring: [short list or image]

## Setup

1. Install [Arduino IDE / PlatformIO] and the [DHT library name].
2. Copy `config.example.h` to `config.h` and set your Wi-Fi details and key.
3. Flash `dht22_integrate.ino`.
4. Run `python receiver.py`.

## Security notes

- Never commit a real key or Wi-Fi password. Use the example config file.
- The demo key is for testing only.
- A fixed or reused nonce breaks Ascon security. [Explain how your code makes each nonce unique.]
