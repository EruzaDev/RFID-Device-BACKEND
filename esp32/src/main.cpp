#include <Arduino.h>
#include <ArduinoJson.h>
#include <HTTPClient.h>
#include <LiquidCrystal_I2C.h>
#include <MFRC522.h>
#include <SPI.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <Wire.h>
#include <esp_system.h>
#include <mbedtls/md.h>
#include <time.h>
#include "secrets.h"

// ESP32 DevKit; buttons connect between the GPIO and GND.
constexpr uint8_t PIN_SCAN = 25;
constexpr uint8_t PIN_MENU = 26;
constexpr uint8_t PIN_BUZZER = 27; // active buzzer module, active HIGH
constexpr uint8_t PIN_RFID_SS = 5;
constexpr uint8_t PIN_RFID_RST = 4;
constexpr uint8_t LCD_ADDRESS = 0x27;

LiquidCrystal_I2C lcd(LCD_ADDRESS, 16, 2);
MFRC522 rfid(PIN_RFID_SS, PIN_RFID_RST);

enum class Step { idle, student, item, confirm };
Step step = Step::idle;
bool borrowMode = true;
String studentUid;
String itemUid;
String requestId;
String readyStudent;
String readyItem;
unsigned long lastConfirmScreenMs = 0;
bool showConfirmNames = true;
bool scanWasDown = false;
bool menuWasDown = false;
unsigned long lastButtonMs = 0;

void screen(const String &line1, const String &line2) {
  lcd.clear();
  lcd.setCursor(0, 0);
  lcd.print(line1.substring(0, 16));
  lcd.setCursor(0, 1);
  lcd.print(line2.substring(0, 16));
  Serial.println(line1 + " | " + line2);
}

void beep(bool good) {
  digitalWrite(PIN_BUZZER, HIGH);
  delay(good ? 100 : 350);
  digitalWrite(PIN_BUZZER, LOW);
}

void idleScreen() {
  screen(borrowMode ? "BORROW mode" : "RETURN mode", "SCAN to start");
}

void reportState(const char *stage);

void resetSession() {
  studentUid = "";
  itemUid = "";
  requestId = "";
  readyStudent = "";
  readyItem = "";
  step = Step::idle;
  idleScreen();
  reportState("idle");
}

String randomHex(size_t bytes) {
  static const char alphabet[] = "0123456789abcdef";
  String value;
  value.reserve(bytes * 2);
  for (size_t i = 0; i < bytes; ++i) {
    uint8_t byte;
    esp_fill_random(&byte, 1);
    value += alphabet[byte >> 4];
    value += alphabet[byte & 15];
  }
  return value;
}

String hexDigest(const uint8_t *data, size_t length) {
  static const char alphabet[] = "0123456789abcdef";
  String result;
  result.reserve(length * 2);
  for (size_t i = 0; i < length; ++i) {
    result += alphabet[data[i] >> 4];
    result += alphabet[data[i] & 15];
  }
  return result;
}

bool decodeSecret(uint8_t *output) {
  String input = DEVICE_SECRET_HEX;
  if (input.length() != 64) return false;
  for (int i = 0; i < 32; ++i) {
    char pair[3] = {input[i * 2], input[i * 2 + 1], 0};
    char *end = nullptr;
    unsigned long byte = strtoul(pair, &end, 16);
    if (end != pair + 2) return false;
    output[i] = static_cast<uint8_t>(byte);
  }
  return true;
}

String signatureFor(const String &path, const String &timestamp,
                    const String &nonce, const String &body) {
  uint8_t secret[32];
  if (!decodeSecret(secret)) return "";
  const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  uint8_t bodyHash[32];
  uint8_t signature[32];
  if (mbedtls_md(md, reinterpret_cast<const unsigned char *>(body.c_str()),
                 body.length(), bodyHash) != 0) return "";
  String signing = "POST\n" + path + "\n" + timestamp + "\n" + nonce +
                   "\n" + hexDigest(bodyHash, 32);
  if (mbedtls_md_hmac(md, secret, sizeof(secret),
                      reinterpret_cast<const unsigned char *>(signing.c_str()),
                      signing.length(), signature) != 0) return "";
  return hexDigest(signature, 32);
}

bool ensureNetwork() {
  if (WiFi.status() != WL_CONNECTED) {
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
    unsigned long deadline = millis() + 12000;
    while (WiFi.status() != WL_CONNECTED && millis() < deadline) delay(150);
  }
  if (WiFi.status() != WL_CONNECTED) return false;
  if (time(nullptr) < 1700000000) {
    configTime(0, 0, "pool.ntp.org", "time.google.com");
    unsigned long deadline = millis() + 12000;
    while (time(nullptr) < 1700000000 && millis() < deadline) delay(150);
  }
  return time(nullptr) >= 1700000000;
}

bool postSigned(const String &path, const String &body, JsonDocument &response) {
  if (!ensureNetwork()) {
    response["message"] = "WiFi or clock down";
    return false;
  }
  char timestampBuffer[24];
  snprintf(timestampBuffer, sizeof(timestampBuffer), "%lld",
           static_cast<long long>(time(nullptr)));
  String timestamp(timestampBuffer);
  String nonce = randomHex(16);
  String signature = signatureFor(path, timestamp, nonce, body);
  if (signature.isEmpty()) {
    response["message"] = "Bad device secret";
    return false;
  }
  WiFiClientSecure client;
  client.setCACert(ROOT_CA);
  HTTPClient http;
  http.setTimeout(8000);
  if (!http.begin(client, String(API_BASE_URL) + path)) {
    response["message"] = "HTTPS setup failed";
    return false;
  }
  http.addHeader("Content-Type", "application/json");
  http.addHeader("X-Device-Id", DEVICE_ID);
  http.addHeader("X-Timestamp", timestamp);
  http.addHeader("X-Nonce", nonce);
  http.addHeader("X-Signature", signature);
  int status = http.POST(body);
  String payload = status > 0 ? http.getString() : "";
  http.end();
  if (status <= 0) {
    response["message"] = "Network/TLS error";
    return false;
  }
  if (deserializeJson(response, payload)) {
    response["message"] = "Bad server reply";
    return false;
  }
  return status == 200 && response["ok"].as<bool>();
}

void reportState(const char *stage) {
  JsonDocument body;
  body["mode"] = borrowMode ? "borrow" : "return";
  body["stage"] = stage;
  String payload;
  serializeJson(body, payload);
  JsonDocument response;
  if (!postSigned("/api/v1/state", payload, response)) {
    Serial.println("Could not report scanner state: " + response["message"].as<String>());
  }
}

String jsonBody(bool includeRequestId) {
  JsonDocument doc;
  doc["mode"] = borrowMode ? "borrow" : "return";
  doc["student_uid"] = studentUid;
  if (itemUid.isEmpty()) doc["item_uid"] = nullptr;
  else doc["item_uid"] = itemUid;
  if (includeRequestId) doc["request_id"] = requestId;
  String result;
  serializeJson(doc, result);
  return result;
}

String readUid() {
  if (!rfid.PICC_IsNewCardPresent() || !rfid.PICC_ReadCardSerial()) return "";
  static const char alphabet[] = "0123456789ABCDEF";
  String uid;
  uid.reserve(rfid.uid.size * 2);
  for (uint8_t i = 0; i < rfid.uid.size; ++i) {
    uid += alphabet[rfid.uid.uidByte[i] >> 4];
    uid += alphabet[rfid.uid.uidByte[i] & 15];
  }
  rfid.PICC_HaltA();
  rfid.PCD_StopCrypto1();
  Serial.println("RFID UID: " + uid);
  return uid;
}

void showFailure(const JsonDocument &response) {
  reportState("error");
  String message = response["message"].as<String>();
  if (message.isEmpty()) message = "Check server";
  screen("NOT ACCEPTED", message);
  beep(false);
  delay(1800);
}

void handleCard(const String &uid) {
  if (step == Step::student) {
    studentUid = uid;
    screen("Checking student", "Please wait...");
    JsonDocument response;
    if (postSigned("/api/v1/preview", jsonBody(false), response)) {
      screen("Student accepted", "Scan item tag");
      beep(true);
      step = Step::item;
      reportState("scan_item");
    } else {
      studentUid = "";
      showFailure(response);
      screen("Scan student ID", "MENU cancels");
      reportState("scan_student");
    }
  } else if (step == Step::item) {
    if (uid == studentUid) {
      screen("Wrong tag", "Scan item tag");
      beep(false);
      delay(900);
      screen("Scan item tag", "MENU cancels");
      return;
    }
    itemUid = uid;
    screen("Checking item", "Please wait...");
    JsonDocument response;
    if (postSigned("/api/v1/preview", jsonBody(false), response)) {
      requestId = randomHex(16);
      readyStudent = response["student_name"].as<String>();
      readyItem = response["item_name"].as<String>();
      showConfirmNames = true;
      lastConfirmScreenMs = millis();
      screen("S:" + readyStudent, "I:" + readyItem);
      beep(true);
      step = Step::confirm;
      reportState("confirm");
    } else {
      itemUid = "";
      showFailure(response);
      screen("Scan item tag", "MENU cancels");
      reportState("scan_item");
    }
  }
}

void handleScan() {
  if (step == Step::idle) {
    step = Step::student;
    screen("Scan student ID", "MENU cancels");
    reportState("scan_student");
  } else if (step == Step::confirm) {
    screen("Saving record", "Please wait...");
    JsonDocument response;
    if (postSigned("/api/v1/commit", jsonBody(true), response)) {
      screen(borrowMode ? "BORROW recorded" : "RETURN recorded", "Input is correct");
      beep(true);
      reportState("success");
      delay(2200);
      resetSession();
    } else {
      showFailure(response);
      screen("SCAN to retry", "MENU cancels");
      reportState("confirm");
    }
  } else {
    screen(step == Step::student ? "Scan student ID" : "Scan item tag", "MENU cancels");
  }
}

void setup() {
  Serial.begin(115200);
  pinMode(PIN_SCAN, INPUT_PULLUP);
  pinMode(PIN_MENU, INPUT_PULLUP);
  pinMode(PIN_BUZZER, OUTPUT);
  digitalWrite(PIN_BUZZER, LOW);
  Wire.begin(21, 22);
  lcd.init();
  lcd.backlight();
  SPI.begin(18, 19, 23, PIN_RFID_SS);
  rfid.PCD_Init();
  WiFi.mode(WIFI_STA);
  idleScreen();
  reportState("idle");
}

void loop() {
  bool scanDown = digitalRead(PIN_SCAN) == LOW;
  bool menuDown = digitalRead(PIN_MENU) == LOW;
  if (millis() - lastButtonMs > 180) {
    if (menuDown && !menuWasDown) {
      lastButtonMs = millis();
      if (step == Step::idle) {
        borrowMode = !borrowMode;
        idleScreen();
        reportState("idle");
      } else {
        screen("Cancelled", "No record saved");
        beep(false);
        delay(750);
        resetSession();
      }
    } else if (scanDown && !scanWasDown) {
      lastButtonMs = millis();
      handleScan();
    }
  }
  scanWasDown = scanDown;
  menuWasDown = menuDown;
  if (step == Step::student || step == Step::item) {
    String uid = readUid();
    if (!uid.isEmpty()) handleCard(uid);
  } else if (step == Step::confirm && millis() - lastConfirmScreenMs >= 2500) {
    showConfirmNames = !showConfirmNames;
    lastConfirmScreenMs = millis();
    if (showConfirmNames) screen("S:" + readyStudent, "I:" + readyItem);
    else screen(borrowMode ? "Confirm BORROW" : "Confirm RETURN", "SCAN=OK MENU=NO");
  }
  delay(30);
}
