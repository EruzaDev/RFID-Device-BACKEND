# RFID borrowing and returning

This project has a Python 3 backend and ESP32 firmware for an SPI MFRC522 reader, two buttons, an active buzzer, and a 16×2 I²C LCD. The backend records which registered student borrowed which registered item. Every ESP32 request carries a device ID, timestamp, random nonce, and HMAC-SHA256 signature. The server checks the signature, a five-minute clock window, and nonce reuse; the ESP32 verifies the server's TLS certificate.

## Hardware

The included pin layout targets an ESP32 DevKit. Power the MFRC522 from **3.3 V**. Connect both buttons from their GPIO to GND; internal pull-ups are enabled. Check the voltage of your LCD backpack: many require 5 V and need a bidirectional I²C level shifter to protect ESP32 pins.

| Part | ESP32 pin |
| --- | --- |
| MFRC522 SDA/SS | GPIO 5 |
| MFRC522 RST | GPIO 4 |
| MFRC522 SCK | GPIO 18 |
| MFRC522 MISO | GPIO 19 |
| MFRC522 MOSI | GPIO 23 |
| LCD SDA / SCL | GPIO 21 / 22 |
| Scan button | GPIO 25 |
| Menu button | GPIO 26 |
| Active buzzer signal | GPIO 27 |

The LCD address is set to `0x27` in `esp32/src/main.cpp`; change it if your backpack uses `0x3F`. An active buzzer module is assumed. A bare buzzer may need a driver transistor and different signal code.

## Set up the backend

No Python packages are required. Run these commands from the repository root:

```sh
python3 -m rfid_backend add-student A1B2C3D4 "Alice Santos"
python3 -m rfid_backend add-item 01020304 "Science Book"
python3 -m rfid_backend add-device scanner-1
```

The final command prints a 64-character hex secret. Copy it to the ESP32 configuration. Keep the database and firmware secrets private. To revoke a lost scanner, run `python3 -m rfid_backend disable-device scanner-1`. To reject a lost card or tag, use `disable-student UID` or `disable-item UID`. `python3 -m rfid_backend list-loans` shows records and whether each loan is open.

UIDs must be uppercase hexadecimal with 8, 14, or 20 characters (4, 7, or 10 bytes). The firmware prints scanned UIDs on the serial monitor if needed for registration. Use one student card and one item tag; the reader expects the student card first.

The backend serves HTTPS itself. For a local network, create a certificate whose Subject Alternative Name matches the server IP (replace the sample IP):

```sh
openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 365 \
  -keyout server.key -out server.pem -subj '/CN=RFID backend' \
  -addext 'subjectAltName=IP:192.168.1.50'
python3 -m rfid_backend serve --host 0.0.0.0 --port 8443 --cert server.pem --key server.key
```

Use a fixed LAN IP or DNS name and regenerate the certificate if it changes. With a DNS name, use `DNS:your-name` for the SAN. Place the same `server.pem` certificate in the firmware's `ROOT_CA`. Protect `server.key` and `rfid.sqlite3`; generated database files are created with owner-only permissions. Open TCP port 8443 only to your trusted network. The ESP32 needs Wi-Fi and NTP access to sign time-bound requests.

## Flash the ESP32

Install [PlatformIO](https://docs.platformio.org/en/latest/core/installation/index.html). Copy `esp32/include/secrets.h.example` to `esp32/include/secrets.h` and fill in Wi-Fi, backend URL, device ID, printed secret, and full PEM certificate. Build and upload from `esp32/`:

```sh
pio run -t upload
pio device monitor
```

`secrets.h` is ignored by Git. The backend URL must start with `https://` and match the certificate SAN. Never use a TLS client mode that skips certificate verification.

## Use the scanner

Menu switches between **BORROW** and **RETURN** while idle. Press Scan to start. Present the student card, remove it, then present the item tag. The backend checks both registrations and whether the item can be borrowed or returned by that student. The LCD alternates the student and item names with `SCAN=OK MENU=NO`; press Scan again to record it. Menu cancels any unfinished session. The buzzer gives a short sound for accepted input and a longer sound for rejection. If the network fails during confirmation, press Scan to retry; the same request ID prevents a duplicate loan or return.

The LCD shows `Input is correct` only after the backend confirms a saved record. The ESP32 never queues transactions while offline.

## API protocol

`POST /api/v1/preview` accepts `{"mode":"borrow","student_uid":"A1B2C3D4","item_uid":null}` after the student scan, then the same body with an item UID after the item scan. `POST /api/v1/commit` requires both UIDs and a random 32-character lowercase hex `request_id`. The server rechecks state while writing the record. `GET /api/v1/health` returns health status.

Each POST includes `X-Device-Id`, `X-Timestamp` (Unix seconds), `X-Nonce` (32 lowercase hex characters), and `X-Signature` (HMAC-SHA256, lowercase hex). Calculate the HMAC with the 32-byte device secret over these UTF-8 bytes:

```text
POST\n/api/v1/preview\n<TIMESTAMP>\n<NONCE>\n<SHA256_HEX_OF_EXACT_JSON_BODY>
```

Use the actual path for each request. Repeating a nonce is rejected, even with a new signature. Repeating a committed `request_id` with the same data returns the original result; changing its data is rejected.

**Card security limit:** MFRC522 reads a card UID, which can be copied or emulated. This system verifies an enrolled UID and authenticates the ESP32, but a UID alone is not strong proof of a student's identity. If identity assurance matters, use cryptographic cards/readers and card challenge-response authentication.

## Tests

```sh
python3 -m unittest discover -s tests -v
```
