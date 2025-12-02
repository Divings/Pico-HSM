import sys
import json
import os
import ubinascii
import machine
import uhashlib
import time
import urandom
import hashlib
from machine import Pin, unique_id
import array
import rp2

# ----------------------------------------------------------
# WS2812B (あなたの元コードをそのまま維持)
# ----------------------------------------------------------
@rp2.asm_pio(sideset_init=rp2.PIO.OUT_LOW, out_shiftdir=rp2.PIO.SHIFT_LEFT, autopull=True, pull_thresh=24)
def ws2812():
    T1 = 2
    T2 = 5
    T3 = 3
    wrap_target()
    label("bitloop")
    out(x, 1)               .side(0)    [T3 - 1]
    jmp(not_x, "do_zero")   .side(1)    [T1 - 1]
    jmp("bitloop")          .side(1)    [T2 - 1]
    label("do_zero")
    nop()                   .side(0)    [T2 - 1]
    wrap()

class ws2812b:
    def __init__(self, num_leds, sm, pin, delay=0.001):
        self.pixels = array.array("I", [0 for _ in range(num_leds)])
        self.sm = rp2.StateMachine(sm, ws2812, freq=8000000, sideset_base=Pin(pin))
        self.sm.active(1)
        self.num_leds = num_leds
        self.delay = delay
        self.brightnessvalue = 255

    def set_pixel(self, n, r, g, b):
        r = round(r * (self.brightnessvalue / 255))
        g = round(g * (self.brightnessvalue / 255))
        b = round(b * (self.brightnessvalue / 255))
        self.pixels[n] = b | (r << 8) | (g << 16)

    def fill(self, r, g, b):
        for i in range(self.num_leds):
            self.set_pixel(i, r, g, b)
        self.show()

    def show(self):
        for pix in self.pixels:
            self.sm.put(pix, 8)
        time.sleep(self.delay)

# ----------------------------------------------------------
# LED / 初期化
# ----------------------------------------------------------
NEO = ws2812b(1, 0, 19)
NEO.fill(0,0,0)
LED = Pin(25, Pin.OUT)
LED.value(0)

RAW_UID = machine.unique_id()
DEVICE_ID = ubinascii.hexlify(RAW_UID).decode().upper()

def flash_led():
    NEO.fill(30, 180, 30)
    time.sleep(0.08)
    NEO.fill(0,0,0)

MASTER_SEED_FILE = "master.seed"
HMAC_KEY_FILE    = "hsm_hmac.key"
KEYPART_FILE     = "hsm_keypart.key"
FW_VERSION       = "1.5.0-SAVED"

# ----------------------------------------------------------
# master.seed 読み込み or 生成
# ----------------------------------------------------------
def load_master_seed():
    try:
        with open(MASTER_SEED_FILE, "rb") as f:
            data = f.read()
            if len(data) == 32:
                return data
    except:
        pass

    seed = os.urandom(32)
    with open(MASTER_SEED_FILE, "wb") as f:
        f.write(seed)
    return seed

MASTER_SEED = load_master_seed()

# ----------------------------------------------------------
# SHA256 KDF (master.seed + RAW_UID)
# ----------------------------------------------------------
def derive_key():
    raw = MASTER_SEED + RAW_UID
    return hashlib.sha256(raw).digest()

ENC_KEY = derive_key()

# ----------------------------------------------------------
# XOR 暗号
# ----------------------------------------------------------
def xor_stream(data: bytes, key: bytes) -> bytes:
    out = bytearray(len(data))
    kl = len(key)
    for i in range(len(data)):
        out[i] = data[i] ^ key[i % kl]
    return bytes(out)

# ----------------------------------------------------------
# 安全ランダム生成
# ----------------------------------------------------------
def secure_random_bytes(n):
    return bytes([urandom.getrandbits(8) for _ in range(n)])

# ----------------------------------------------------------
# 保存されたキーを読み込み / 作成
# ----------------------------------------------------------
def load_or_create_key(path, size):
    if path in os.listdir():
        try:
            with open(path, "rb") as f:
                enc = f.read()
            dec = xor_stream(enc, ENC_KEY)
            if len(dec) == size:
                return dec
        except:
            pass

    key = secure_random_bytes(size)
    enc = xor_stream(key, ENC_KEY)

    with open(path, "wb") as f:
        f.write(enc)

    return key

SECRET_HMAC_KEY    = load_or_create_key(HMAC_KEY_FILE, 32)
SECRET_AES_KEYPART = load_or_create_key(KEYPART_FILE, 16)

# ----------------------------------------------------------
# HMAC-SHA256
# ----------------------------------------------------------
def hmac_sha256(key, msg):
    block = 64
    if len(key) > block:
        key = uhashlib.sha256(key).digest()
    key = key + b"\x00" * (block - len(key))

    o_key_pad = bytes((b ^ 0x5C) for b in key)
    i_key_pad = bytes((b ^ 0x36) for b in key)
    return uhashlib.sha256(o_key_pad + uhashlib.sha256(i_key_pad + msg).digest()).digest()

# ----------------------------------------------------------
# コマンド処理
# ----------------------------------------------------------
def process_request(obj):

    if "cmd" not in obj:
        return {"error": "missing cmd"}

    cmd = obj["cmd"]

    if cmd == "hmac":
        try:
            raw = ubinascii.a2b_base64(obj["data"])
            mac = hmac_sha256(SECRET_HMAC_KEY, raw)
            return {"hmac": ubinascii.b2a_base64(mac).decode().strip()}
        except:
            return {"error": "hmac failed"}

    if cmd == "keypart":
        return {"keypart": ubinascii.b2a_base64(SECRET_AES_KEYPART).decode().strip()}

    if cmd == "info":
        return {
            "device": DEVICE_ID,
            "uid_raw": ubinascii.hexlify(RAW_UID).decode(),
            "version": FW_VERSION,
            "features": [
                "HMAC256",
                "KEYPART128",
                "UID_KDF",
                "ENCRYPTED_STORAGE",
                "LED_FEEDBACK",
            ]
        }

    if cmd == "sleep":
        for _ in range(4):
            LED.value(1); time.sleep(0.1)
            LED.value(0); time.sleep(0.1)
        machine.idle()
        return {"status": "sleep"}

    if cmd == "shutdown":
        for _ in range(2):
            NEO.fill(0,0,255); time.sleep(0.1)
            NEO.fill(0,0,0); time.sleep(0.1)
        print(json.dumps({"status":"Shutdown"}))
        time.sleep(0.1)
        LED.value(0)
        machine.lightsleep()
        return None

    return {"error":"unknown cmd"}

# ----------------------------------------------------------
# メインループ
# ----------------------------------------------------------
def main():
    while True:
        line = sys.stdin.readline()
        if not line:
            time.sleep(0.02)
            continue
        
        flash_led()

        try:
            obj = json.loads(line.strip())
        except:
            print(json.dumps({"error":"invalid json"}))
            continue

        res = process_request(obj)
        if res is not None:
            print(json.dumps(res))

main()
