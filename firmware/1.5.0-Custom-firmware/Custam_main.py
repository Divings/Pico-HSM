import sys
import json
import os
import ubinascii
import machine
import uhashlib
import time
from machine import Pin

LED = Pin("LED", Pin.OUT)
LED.value(0)

MASTER_SEED_FILE = "master.seed"
DEVICE_ID = "PICO-HSM"
FW_VERSION = "1.5.0-UID-ENC-SLEEP"

# ----------------------------------------------------------
# MASTER SEED 読み込み or 生成 (あなたのコードそのまま)
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
# HMAC-SHA256 (あなたの独自実装を保持)
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
# AES鍵の代わりとなる keypart（128bit）
# ----------------------------------------------------------
SECRET_AES_KEYPART = os.urandom(16)

# ----------------------------------------------------------
# 固有ID取得 & UID-KDF
# ----------------------------------------------------------
def read_uid():
    try:
        with open("unique.id", "rb") as f:
            raw = f.read()
            if len(raw) == 17:
                return raw
    except:
        pass

    raw = b"X" * 17
    return raw


RAW_UID = read_uid()
KDF_KEY = hmac_sha256(MASTER_SEED, RAW_UID)

# ----------------------------------------------------------
# XOR暗号 (あなたの実装を完全維持)
# ----------------------------------------------------------
def xor_encrypt(data, key):
    out = bytearray(len(data))
    for i in range(len(data)):
        out[i] = data[i] ^ key[i % len(key)]
    return bytes(out)

# ----------------------------------------------------------
# メインコマンド処理
# ----------------------------------------------------------
def process_request(obj):

    if "cmd" not in obj:
        return {"error": "missing cmd"}

    cmd = obj["cmd"]

    # ------------------------------------------------------
    # HMAC (あなたの既存機能)
    # ------------------------------------------------------
    if cmd == "hmac":
        try:
            raw = ubinascii.a2b_base64(obj["data"])
            mac = hmac_sha256(KDF_KEY, raw)
            return {
                "hmac": ubinascii.b2a_base64(mac).decode().strip()
            }
        except:
            return {"error": "hmac failed"}

    # ------------------------------------------------------
    # KEY PART (あなたの既存機能)
    # ------------------------------------------------------
    if cmd == "keypart":
        return {
            "keypart": ubinascii.b2a_base64(SECRET_AES_KEYPART).decode().strip()
        }

    # ------------------------------------------------------
    # INFO (あなたの既存機能)
    # ------------------------------------------------------
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
                "SLEEP_MODE"
            ]
        }

    # ------------------------------------------------------
    # ★ SLEEP MODE（軽スリープ：USB維持 / CPU idle）
    # ------------------------------------------------------
    if cmd == "sleep":

        # LED 4回点滅（あなたの指定）
        for _ in range(4):
            LED.value(1); time.sleep(0.1)
            LED.value(0); time.sleep(0.1)

        # USB alive のままCPU待機
        machine.idle()
        return {"status": "sleep"}

    # ------------------------------------------------------
    # ★ SHUTDOWN（既存lightsleepを維持）
    # ------------------------------------------------------
    if cmd == "shutdown":

        # LED 2回点滅（あなたが元から使っていたパターン）
        for _ in range(2):
            LED.value(1); time.sleep(0.1)
            LED.value(0); time.sleep(0.1)
        a={"status":"Shutdown"}
        print(json.dumps(a))
        time.sleep(0.1)
        machine.lightsleep()
        return None

    # ------------------------------------------------------
    # 不明コマンド
    # ------------------------------------------------------
    return {"error": "unknown cmd"}


# ----------------------------------------------------------
# メインループ（print使用、あなたの形式通り）
# ----------------------------------------------------------
def main():
    LED.value(0)

    while True:
        line = sys.stdin.readline()
        if not line:
            time.sleep(0.02)
            continue

        try:
            obj = json.loads(line.strip())
        except:
            print(json.dumps({"error": "invalid json"}))
            continue

        res = process_request(obj)
        if res is not None:
            print(json.dumps(res))


# 実行
main()

