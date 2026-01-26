#include <Arduino.h>
#include <DHT.h>
#include <Preferences.h>
#include "esp_system.h"

extern "C" {
  #include "ascon_aead.h"
}

// ================== DHT22 ==================
#define DHTPIN 4
#define DHTTYPE DHT22
DHT dht(DHTPIN, DHTTYPE);

// ================== ASCON ==================
// 1 = Ascon-128a, 0 = Ascon-128
#define USE_ASCON_128A 1

static const uint8_t KEY[16] = {
  0x60,0x1D,0x3A,0x99,0x12,0x7B,0x4C,0x55,0xA7,0x9E,0x80,0x0F,0x33,0x21,0x7C,0x42
};

static const char* DEVICE_ID = "esp32-dht22-001"; // used as Associated Data (AD)

// ---- Replay/nonce safety (good protocol practice) ----
// nonce = devNonce(8) || seq(8)
Preferences prefs;
static uint64_t devNonce = 0;
static uint64_t seqCtr   = 0;

// Store last encrypted packet so we can decrypt later
static bool   have_last = false;
static uint8_t last_nonce[16];
static uint8_t last_c[512];
static size_t  last_clen = 0;
static size_t  last_plen = 0;

static String hexEncode(const uint8_t* data, size_t len) {
  static const char HEXCHARS[] = "0123456789ABCDEF";
  String out; out.reserve(len * 2);
  for (size_t i = 0; i < len; ++i) {
    out += HEXCHARS[(data[i] >> 4) & 0x0F];
    out += HEXCHARS[data[i] & 0x0F];
  }
  return out;
}

static void u64_to_be(uint64_t x, uint8_t out8[8]) {
  out8[0] = (uint8_t)(x >> 56);
  out8[1] = (uint8_t)(x >> 48);
  out8[2] = (uint8_t)(x >> 40);
  out8[3] = (uint8_t)(x >> 32);
  out8[4] = (uint8_t)(x >> 24);
  out8[5] = (uint8_t)(x >> 16);
  out8[6] = (uint8_t)(x >>  8);
  out8[7] = (uint8_t)(x >>  0);
}

static void buildNonce(uint8_t nonce[16], uint64_t devN, uint64_t seq) {
  u64_to_be(devN, nonce);
  u64_to_be(seq, nonce + 8);
}

static int aead_encrypt(uint8_t *c, size_t *clen,
                        const uint8_t *m, size_t mlen,
                        const uint8_t *ad, size_t adlen,
                        const uint8_t *npub, const uint8_t *k) {
#if USE_ASCON_128A
  return ascon_aead128a_encrypt(c, clen, m, mlen, ad, adlen, npub, k);
#else
  return ascon_aead128_encrypt(c, clen, m, mlen, ad, adlen, npub, k);
#endif
}

static int aead_decrypt(uint8_t *m, size_t *mlen,
                        const uint8_t *c, size_t clen,
                        const uint8_t *ad, size_t adlen,
                        const uint8_t *npub, const uint8_t *k) {
#if USE_ASCON_128A
  return ascon_aead128a_decrypt(m, mlen, c, clen, ad, adlen, npub, k);
#else
  return ascon_aead128_decrypt(m, mlen, c, clen, ad, adlen, npub, k);
#endif
}

static void encryptAndPrint(const String& plaintext, uint64_t seqUsed) {
  const uint8_t* pt = (const uint8_t*)plaintext.c_str();
  size_t plen = plaintext.length();

  uint8_t nonce[16];
  buildNonce(nonce, devNonce, seqUsed);

  // AD protects metadata integrity too
  String adStr = String("dev=") + DEVICE_ID + "|seq=" + String((unsigned long long)seqUsed);
  const uint8_t* ad = (const uint8_t*)adStr.c_str();
  size_t adlen = adStr.length();

  uint8_t outbuf[512];
  size_t clen = 0;

  uint32_t t0 = micros();
  int rc = aead_encrypt(outbuf, &clen, pt, plen, ad, adlen, nonce, KEY);
  uint32_t t1 = micros();

  if (rc != 0) {
    Serial.println(F("{\"error\":\"encrypt failed\"}"));
    return;
  }

  // Typical AEAD: clen = plen + 16 tag
  if (clen != plen + 16) {
    Serial.println(F("{\"error\":\"unexpected length: your ASCON impl differs\"}"));
    return;
  }

  // store last packet
  memcpy(last_nonce, nonce, 16);
  memcpy(last_c, outbuf, clen);
  last_clen = clen;
  last_plen = plen;
  have_last = true;

  const uint8_t* ct  = outbuf;
  const uint8_t* tag = outbuf + plen;

  String msg = String("{\"nonce\":\"") + hexEncode(nonce, 16) +
               "\",\"ct\":\"" + hexEncode(ct, plen) +
               "\",\"tag\":\"" + hexEncode(tag, 16) +
               "\",\"ad\":\"" + adStr + "\"," +
               "\"enc_us\":" + String((uint32_t)(t1 - t0)) +
               "}";
  Serial.println(msg);
}

static void decryptLast() {
  if (!have_last) {
    Serial.println(F("{\"error\":\"no stored ciphertext\"}"));
    return;
  }

  // Recover seq from nonce (last 8 bytes big-endian)
  uint64_t seqUsed = 0;
  for (int i = 0; i < 8; i++) seqUsed = (seqUsed << 8) | last_nonce[8 + i];

  String adStr = String("dev=") + DEVICE_ID + "|seq=" + String((unsigned long long)seqUsed);
  const uint8_t* ad = (const uint8_t*)adStr.c_str();
  size_t adlen = adStr.length();

  uint8_t m[512];
  size_t mlen = 0;

  uint32_t t0 = micros();
  int rc = aead_decrypt(m, &mlen, last_c, last_clen, ad, adlen, last_nonce, KEY);
  uint32_t t1 = micros();

  if (rc != 0) {
    Serial.println(F("{\"error\":\"decrypt failed (tag mismatch / integrity fail)\"}"));
    return;
  }

  if (mlen >= sizeof(m)) mlen = sizeof(m) - 1;
  m[mlen] = 0;

  String msg = String("{\"dec_plaintext\":\"") + (char*)m +
               "\",\"dec_us\":" + String((uint32_t)(t1 - t0)) +
               "}";
  Serial.println(msg);
}

void setup() {
  Serial.begin(115200);
  while (!Serial) {}

  dht.begin();

  // persistent nonce + counter (good protocol hygiene)
  prefs.begin("ascon", false);
  devNonce = prefs.getULong64("devnonce", 0);
  if (devNonce == 0) {
    devNonce = ((uint64_t)esp_random() << 32) | esp_random();
    if (devNonce == 0) devNonce = 1;
    prefs.putULong64("devnonce", devNonce);
  }
  seqCtr = prefs.getULong64("seq", 0);

  Serial.println(F("{\"ready\":true,\"cmds\":\"READ=read+encrypt, DEC=decrypt last\"}"));
#if USE_ASCON_128A
  Serial.println(F("{\"variant\":\"Ascon-128a\"}"));
#else
  Serial.println(F("{\"variant\":\"Ascon-128\"}"));
#endif

  // WARNING about placeholder AEAD
  Serial.println(F("{\"note\":\"If your ascon_aead.c is the dummy AA-tag version, this is NOT real security yet.\"}"));
}

void loop() {
  if (!Serial.available()) return;

  String cmd = Serial.readStringUntil('\n');
  cmd.trim();

  if (cmd.equalsIgnoreCase("READ")) {
    float t = dht.readTemperature();
    float h = dht.readHumidity();

    if (isnan(t) || isnan(h)) {
      Serial.println(F("{\"error\":\"DHT22 read failed\"}"));
      return;
    }
    seqCtr++;
    prefs.putULong64("seq", seqCtr);

    String plaintext = String("{\"temp\":") + String(t, 2) +
                   String(",\"hum\":") + String(h, 2) +
                   String(",\"ts\":") + String(millis()) +
                   String(",\"seq\":") + String((unsigned long long)seqCtr) +
                   String("}");


    encryptAndPrint(plaintext, seqCtr);

  } else if (cmd.equalsIgnoreCase("DEC")) {
    decryptLast();

  } else {
    Serial.println(F("{\"help\":\"Commands: READ, DEC\"}"));
  }
}
