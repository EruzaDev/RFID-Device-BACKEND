#pragma once

#include <Arduino.h>
#include <ArduinoJson.h>
#include <LiquidCrystal_I2C.h>
#include <MFRC522.h>
#include <SPI.h>
#include <Wire.h>
#include <esp_system.h>

// ESP32 DevKit; buttons connect between the GPIO and GND.
constexpr uint8_t PIN_SCAN = 25;
constexpr uint8_t PIN_MENU = 26;
constexpr uint8_t PIN_BUZZER = 27; // active buzzer module, active HIGH
constexpr uint8_t PIN_LED_GREEN = 32;
constexpr uint8_t PIN_LED_RED = 33;
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

enum class ResultLight { off, success, failure };

void setResultLight(ResultLight result) {
  digitalWrite(PIN_LED_GREEN, result == ResultLight::success ? HIGH : LOW);
  digitalWrite(PIN_LED_RED, result == ResultLight::failure ? HIGH : LOW);
}

void idleScreen() {
  screen(borrowMode ? "BORROW mode" : "RETURN mode", "SCAN to start");
}

void reportState(const char *stage, const char *errorCode = nullptr);

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

// The laptop owns the API secret and HTTPS connection. Only @RFID: lines are
// protocol frames; the other Serial prints are readable diagnostic messages.
bool postViaLaptop(const String &path, const String &body, JsonDocument &response) {
  String id = randomHex(8);
  JsonDocument request;
  request["id"] = id;
  request["path"] = path;
  JsonDocument parsedBody;
  if (deserializeJson(parsedBody, body)) {
    response["message"] = "Bad scanner JSON";
    return false;
  }
  request["body"] = parsedBody.as<JsonVariant>();
  Serial.print("@RFID:");
  serializeJson(request, Serial);
  Serial.println();

  unsigned long started = millis();
  while (millis() - started < 12000) {
    if (!Serial.available()) {
      delay(10);
      continue;
    }
    String line = Serial.readStringUntil('\n');
    if (!line.startsWith("@RFID:")) continue;
    JsonDocument reply;
    if (deserializeJson(reply, line.substring(6))) continue;
    if (reply["id"].as<String>() != id) continue;
    if (!reply["body"].is<JsonObject>()) break;
    response.set(reply["body"]);
    return reply["status"].as<int>() == 200 && response["ok"].as<bool>();
  }
  response["code"] = "bridge_offline";
  response["message"] = "Laptop bridge offline";
  return false;
}

void reportState(const char *stage, const char *errorCode) {
  JsonDocument body;
  body["mode"] = borrowMode ? "borrow" : "return";
  body["stage"] = stage;
  if (errorCode != nullptr) body["error_code"] = errorCode;
  String payload;
  serializeJson(body, payload);
  JsonDocument response;
  if (!postViaLaptop("/api/v1/state", payload, response)) {
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

// Only fixed codes reach the public process table; raw responses stay on the LCD.
const char *publicErrorCode(const JsonDocument &response) {
  const char *code = response["code"] | "unknown";
  const char *allowed[] = {"student_unknown", "item_unknown", "already_borrowed",
    "wrong_borrower", "bad_uid", "clock_skew", "auth_failed", "replay",
    "request_reused", "server_error", "bridge_offline", "api_unreachable"};
  for (const char *candidate : allowed) if (strcmp(code, candidate) == 0) return candidate;
  return "unknown";
}

void showFailure(const JsonDocument &response) {
  setResultLight(ResultLight::failure);
  reportState("error", publicErrorCode(response));
  String message = response["message"].as<String>();
  if (message.isEmpty()) message = "Check server";
  screen("NOT ACCEPTED", message);
  beep(false);
  delay(1800);
}

void handleCard(const String &uid) {
  setResultLight(ResultLight::off);
  if (step == Step::student) {
    studentUid = uid;
    screen("Checking student", "Please wait...");
    reportState("checking_student");
    JsonDocument response;
    if (postViaLaptop("/api/v1/preview", jsonBody(false), response)) {
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
      setResultLight(ResultLight::failure);
      screen("Wrong tag", "Scan item tag");
      reportState("wrong_tag");
      beep(false);
      delay(900);
      screen("Scan item tag", "MENU cancels");
      reportState("scan_item");
      return;
    }
    itemUid = uid;
    screen("Checking item", "Please wait...");
    reportState("checking_item");
    JsonDocument response;
    if (postViaLaptop("/api/v1/preview", jsonBody(false), response)) {
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
  setResultLight(ResultLight::off);
  if (step == Step::idle) {
    step = Step::student;
    screen("Scan student ID", "MENU cancels");
    reportState("scan_student");
  } else if (step == Step::confirm) {
    screen("Saving record", "Please wait...");
    reportState("saving");
    JsonDocument response;
    if (postViaLaptop("/api/v1/commit", jsonBody(true), response)) {
      setResultLight(ResultLight::success);
      screen(borrowMode ? "BORROW recorded" : "RETURN recorded", "Input is correct");
      beep(true);
      reportState("success");
      delay(2200);
      resetSession();
    } else {
      showFailure(response);
      screen("SCAN to retry", "MENU cancels");
      reportState("retry_confirm", publicErrorCode(response));
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
  pinMode(PIN_LED_GREEN, OUTPUT);
  pinMode(PIN_LED_RED, OUTPUT);
  digitalWrite(PIN_BUZZER, LOW);
  setResultLight(ResultLight::off);
  Wire.begin(21, 22);
  lcd.init();
  lcd.backlight();
  SPI.begin(18, 19, 23, PIN_RFID_SS);
  rfid.PCD_Init();
  idleScreen();
  reportState("idle");
}

void loop() {
  bool scanDown = digitalRead(PIN_SCAN) == LOW;
  bool menuDown = digitalRead(PIN_MENU) == LOW;
  if (millis() - lastButtonMs > 180) {
    if (menuDown && !menuWasDown) {
      lastButtonMs = millis();
      setResultLight(ResultLight::off);
      if (step == Step::idle) {
        borrowMode = !borrowMode;
        idleScreen();
        reportState("idle");
      } else {
        screen("Cancelled", "No record saved");
        reportState("cancelled");
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
