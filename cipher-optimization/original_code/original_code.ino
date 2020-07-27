#pragma GCC optimize("-O3")

#define ROUND_NUM 128

typedef unsigned char u8;
typedef unsigned short u16;

u8 ROL8(u8 x, u8 n) {
  return ((u8)((x) << (n)) | (u8)((x) >> (8 - (n))));
}

u16 ROL16(u16 x, u16 n) {
  return ((u16)((x) << (n)) | (u16)((x) >> (16 - (n))));
}

void key_gen(u8 *rnd, u8 *key) {
  u8 key_in[2];
  u8 tmp1, tmp2;
  u16 *key_p;
  u16 con = 0x9ABC;

  key_in[0] = key[0];
  key_in[1] = key[1];
  key_p = (u16*) key_in;
  int i;
  for (i = 0; i < ROUND_NUM; i++) {
    if (i % 2 == 0) {
      key_in[0] = ROL8(key_in[0], 1) + ROL8(key_in[0], 5);
      key_in[1] = ROL8(key_in[1], 3) + ROL8(key_in[1], 7);
    } else {
      *key_p = ROL16(*key_p, 1) + ROL16(*key_p, 9) + ROL16(con, (i%16));
    }
    tmp1 = key_in[0] + key_in[1];
    tmp2 = key_in[0] ^ key_in[1];
    key_in[0] = tmp1;
    key_in[1] = tmp2;
    rnd[i * 2 + 0] = key_in[0];
    rnd[i * 2 + 1] = key_in[1];
  }
}

void enc(u8 *text, u8 *rnd) {
  u8 text_in[2];
  u16 *text_p;
  text_in[0] = text[0];
  text_in[1] = text[1];
  text_p = (u16*) text_in;
  int i;
  for (i = 0; i < ROUND_NUM; i++) {
    if (i % 2 == 0) {
      *text_p = ROL16(*text_p, 4);
    } else {
      *text_p = ROL16(*text_p, 8);
    }
    text_in[0] = text_in[0] + rnd[i * 2 + 0];
    text_in[1] = text_in[1] ^ rnd[i * 2 + 1];
  }
  text[0] = text_in[0];
  text[1] = text_in[1];
}


u8 TEST_VECTOR(u8 *in, u8 *answer) {
  return (in[0] == answer[0] && in[1] == answer[1]);
}

void setup() {
  Serial.begin(115200);
  pinMode(LED_BUILTIN, OUTPUT);
  u8 key[3][2] = {{0x12, 0x34}, {0x9A, 0xBD}, {0x11, 0x22}};
  u8 rnd[ROUND_NUM * 2] = {
    0,
  };
  u8 text[3][2] = {{0x56, 0x78}, {0xDE, 0xF0}, {0x33, 0x44}};
  u8 out_text[3][2] = {{0x50, 0x3F}, {0x88, 0x28}, {0x7F, 0x33}};
  Serial.println("-----------------");
  Serial.println(" TEST VECTOR ");
  Serial.println("-----------------");
  for (int i = 0; i < 3; i++) {
    key_gen(rnd, key[i]);
    enc(text[i], rnd);
    if (TEST_VECTOR(text[i], out_text[i])) {
      Serial.println(">> CORRECT");
    } else {
      Serial.println(">> WRONG");
    }
  }
  Serial.println("-----------------");
  Serial.println(" BENCHMARK ");
  Serial.println("-----------------");
  u8 key_bench[2] = {0x12, 0x34};
  u8 text_bench[2] = {0x56, 0x78};
  u32 time1;
  u32 time2;
  time1 = millis();
  for (int i = 0; i < 4096; i++) {
    key_gen(rnd, key_bench);
    enc(text_bench, rnd);
    if (text_bench[0] > 0x80) {
      digitalWrite(LED_BUILTIN, HIGH);
    } else {
      digitalWrite(LED_BUILTIN, LOW);
    }
  }
  time2 = millis();
  Serial.print(">> ");
  Serial.println((time2 - time1));
  Serial.println("-----------------");
}

void loop() {}
