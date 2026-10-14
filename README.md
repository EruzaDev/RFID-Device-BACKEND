# RFID equipment borrowing with Supabase

The ESP32 scans the student card and item tag, then sends HMAC-signed HTTPS requests to the `rfid-api` Supabase Edge Function. The function checks registrations and records loans in Supabase Postgres. A browser kiosk subscribes to the public process state; it never receives a card UID or device secret.

The project from the dashboard screenshot is `edelmgnzwcngnozaxrsx`. Its API base URL is:

```text
https://edelmgnzwcngnozaxrsx.supabase.co/functions/v1/rfid-api
```

## Deploy the database and function

Install the [Supabase CLI](https://supabase.com/docs/guides/local-development/cli/getting-started), then run from this repository:

```sh
supabase login
supabase link --project-ref edelmgnzwcngnozaxrsx
supabase db push --dry-run
supabase db push
supabase functions deploy rfid-api --use-api
```

`supabase/migrations/20261014000000_create_rfid_schema.sql` creates the tables and enables Realtime on `device_state`. `supabase/config.toml` sets `verify_jwt = false` because ESP32 requests use device HMAC credentials rather than Supabase JWTs. The function verifies each signed POST and allows public reads only for health, Realtime configuration, and process status. Supabase injects `SUPABASE_DB_URL` into the function; no database URL or privileged key belongs in the frontend or firmware. Only the non-sensitive `device_state` table grants anonymous read access. All other tables have row level security enabled without browser-facing policies.

Do not deploy the function before applying the migration. If your project already has RFID tables or data, inspect `supabase db push --dry-run` first and reconcile them before applying the migration.

## Enroll a scanner, student, and item

Generate a unique 32-byte scanner secret locally:

```sh
python3 -c 'import secrets; print(secrets.token_hex(32))'
```

Use Supabase SQL Editor to run the following, substituting your generated secret and real scanned UIDs. Keep the secret private. UIDs must be uppercase hex with 8, 14, or 20 characters.

```sql
insert into public.devices(id, secret) values ('scanner-1', '<64 lowercase hex characters>');
insert into public.students(uid, name) values ('A1B2C3D4', 'Alice Santos');
insert into public.items(uid, name) values ('01020304', 'Science Book');
```

The device ID and secret must match `esp32/include/secrets.h`. Do not put the secret in a `VITE_` variable or commit it. To revoke a scanner, set `public.devices.active = false` for its ID. The old Python `add-device`, `add-student`, and `add-item` commands write to a local SQLite file and do **not** enroll anything in Supabase.

## Flash the ESP32

Install PlatformIO. Copy `esp32/include/secrets.h.example` to `esp32/include/secrets.h`, fill in Wi-Fi credentials, `API_BASE_URL`, `DEVICE_ID`, `DEVICE_SECRET_HEX`, and the trusted root CA PEM for the Supabase HTTPS endpoint. Keep TLS verification enabled. From `esp32/`:

```sh
pio run -t upload
pio device monitor
```

The MFRC522 reader uses GPIO 5 (SS), 4 (RST), 18 (SCK), 19 (MISO), and 23 (MOSI). The LCD uses GPIO 21/22, the Scan and Menu buttons use GPIO 25/26, and the active buzzer uses GPIO 27. The reader must be powered at 3.3 V. Set the LCD address in `esp32/src/main.cpp` if it is not `0x27`.

Menu chooses BORROW or RETURN while idle. Press Scan, present the student card, present the item tag, then press Scan to confirm the displayed names. Menu cancels an unfinished session. The function rejects unknown/inactive cards and items, already borrowed items, and returns by the wrong student. A repeated confirmation request returns its original result without creating a second loan.

## API

All paths below are appended to the API base URL above. The logical path, such as `/api/v1/preview`, is also the path used in the signature string.

| Method and path | Purpose |
| --- | --- |
| `GET /api/v1/health` | Function health |
| `GET /api/v1/config` | Public Supabase URL and publishable key for Realtime |
| `GET /api/v1/state?device_id=scanner-1` | Read-only mode/stage for the kiosk |
| `POST /api/v1/state` | Signed device process update |
| `POST /api/v1/preview` | Signed student/item validation |
| `POST /api/v1/commit` | Signed, idempotent loan or return |

Each POST includes `X-Device-Id`, `X-Timestamp` (Unix seconds), `X-Nonce` (32 lowercase hex characters), and `X-Signature` (HMAC-SHA256 lowercase hex). Sign these UTF-8 bytes using the device's 32-byte secret:

```text
POST\n<LOGICAL_PATH>\n<TIMESTAMP>\n<NONCE>\n<SHA256_HEX_OF_EXACT_JSON_BODY>
```

The clock must be within five minutes. Nonces cannot be replayed. `preview` accepts `{"mode":"borrow","student_uid":"A1B2C3D4","item_uid":null}` after the student scan, then the same body with the item UID. `commit` also requires a random 32-character lowercase hex `request_id`. `state` accepts a mode (`borrow` or `return`) and stage (`idle`, `scan_student`, `scan_item`, `confirm`, `success`, or `error`). The public state response includes no student or item UID.

The kiosk subscribes to Postgres changes for `device_state` and refreshes state once a minute. This keeps process updates immediate without constant Edge Function polling. The `config` route returns a **publishable** Supabase key, never a privileged database key.

## Checks

```sh
deno check supabase/functions/rfid-api/index.ts
deno lint supabase/functions/rfid-api/index.ts
deno run -A supabase/tests/schema_test.ts
```

**Card security limit:** MFRC522 reads a card UID, which can be copied or emulated. A registered UID and signed scanner request do not prove the cardholder's identity.

## Legacy local server

`rfid_backend/` and `tests/test_backend.py` remain for the earlier standalone Python/SQLite setup and its tests. They are separate from the Supabase deployment. Do not run both backends against the same scanner configuration.
