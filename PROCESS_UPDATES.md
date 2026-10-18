# Scanner process updates

Apply `supabase/migrations/20261018000000_expand_process_stages.sql` after the original migration, then deploy `rfid-api`, deploy the matching UI branch, and flash the firmware. Old firmware bodies containing only mode/stage remain valid. New firmware requires the migration and updated API first.

Public stages now include `checking_student`, `checking_item`, `saving`, `wrong_tag`, `cancelled`, and `retry_confirm`. Fixed error codes describe rejected tags, unavailable API/bridge, authentication, and retry failures; raw LCD text, student UIDs, and names never enter public process state. State timestamps increase monotonically per device to order rapid updates.

Firmware is shared by `arduino/RFIDScanner/RFIDScanner.ino` and `esp32/src/main.cpp`. It uses USB serial through `laptop_bridge.py`, rather than storing a device secret on the ESP32. Install `requirements-bridge.txt`, set `RFID_API_BASE_URL`, `RFID_DEVICE_ID`, and `RFID_DEVICE_SECRET_HEX` on the laptop, and run `python laptop_bridge.py --port <USB-port>`. Firmware wiring remains in the scanner header. Compile with `pio run --project-dir esp32`; flash with `pio run --project-dir esp32 -t upload` after closing programs using the serial port.

Verify with:

```sh
deno test supabase/tests/process_test.ts
deno run -A supabase/tests/schema_test.ts
deno check supabase/functions/rfid-api/index.ts
deno lint supabase/functions/rfid-api supabase/tests
python -m unittest discover -s tests
```

Hardware acceptance: switch modes, begin a scan, tap a student card, tap the equipment tag, and confirm. Check intermediate validation/saving states. Tap the student card during the item step to see `wrong_tag`; MENU cancels and returns to idle. An already borrowed item produces an error code and returns to the item step. Failed commits retain the same request ID for SCAN retries. Disconnect API networking and confirm the LCD and public error/retry state recover when connectivity returns.

The state endpoint stores the latest process only. Realtime delivers brief intermediate stages while connected; fallback polling and reconnects retrieve the latest state and can miss intervening stages. The UI activity list holds the last 12 received updates for the current page session, not a durable event log. If the bridge or API is unreachable, reports cannot reach the site. There is no scanner heartbeat.
