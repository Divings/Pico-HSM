import sys
import ubinascii
import ujson
import hashlib
import urandom
import os
import time
from machine import Pin, unique_id

# =========================================================
#  LED 初期化
# =========================================================
LED = Pin("LED", Pin.OUT)
LED.value(0)

def flash_led():
    LED.value(1)
    time.sleep(0.08)
    LED.value(0)

# =========================================================
#  固有デバイスID（unique_id をそのまま使用）
# =========================================================
RAW_UID = unique_id()  # 例: b"\x01\xAF\x03..."
DEVICE_ID = ubinascii.hexlify(RAW_UID).decode().upper()

# =========================================================
#  設定 / ファイル名
# =========================================================
FW_VERSION     = "1.3.0-UID-ENC-LED"
HMAC_KEY_FILE  = "hsm_hmac.key"
KEYPART_FILE   = "hsm_keypart.key"

# MASTER_SEED（外部流出しない固定データ）
MASTER_SEED = b""

# =========================================================
#  安全なランダム生成
# =========================================================
def secure_random_bytes(n):
    return bytes([urandom.getrandbits(8) for _ in range(n)])

# =========================================================
#  KDF: EncKey = SHA256( MASTER_SEED + UniqueID )
# =========================================================
def derive_key():
    raw = MASTER_SEED + RAW_UID
    return hashlib.sha256(raw).digest()  # 32 bytes

ENC_KEY = derive_key()

# =========================================================
#  XORストリーム暗号（軽量・高速）
# =========================================================
def xor_stream(data: bytes, key: bytes) -> bytes:
    out = bytearray(len(data))
    kl = len(key)
    for i in range(len(data)):
        out[i] = data[i] ^ key[i % kl]
    return bytes(out)

# =========================================================
#  鍵を暗号化して保存 / 復号して読み込み
# =========================================================
def load_or_create_key(path, size):

    # 既存 → 復号して返す
    if path in os.listdir():
        try:
            with open(path, "rb") as f:
                enc = f.read()
            dec = xor_stream(enc, ENC_KEY)
            if len(dec) == size:
                return dec
        except:
            pass  # 壊れているので再生成する

    # 新規生成
    key = secure_random_bytes(size)
    enc = xor_stream(key, ENC_KEY)

    with open(path, "wb") as f:
        f.write(enc)

    return key

# =========================================================
#  鍵読み込み
# =========================================================
SECRET_HMAC_KEY    = load_or_create_key(HMAC_KEY_FILE, 32)
SECRET_AES_KEYPART = load_or_create_key(KEYPART_FILE, 16)

# =========================================================
#  HMAC-SHA256
# =========================================================
def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    block = 64
    if len(key) > block:
        key = hashlib.sha256(key).digest()
    if len(key) < block:
        key += b"\x00" * (block - len(key))

    o_key = bytes((x ^ 0x5C) for x in key)
    i_key = bytes((x ^ 0x36) for x in key)

    inner = hashlib.sha256(i_key + msg).digest()
    return hashlib.sha256(o_key + inner).digest()

# =========================================================
#  コマンド処理
# =========================================================
def process_request(obj):

    if "cmd" not in obj:
        return {"error": "missing cmd"}

    cmd = obj["cmd"]

    # ---------------------
    # HMAC
    # ---------------------
    if cmd == "hmac":
        try:
            raw = ubinascii.a2b_base64(obj["data"])
            mac = hmac_sha256(SECRET_HMAC_KEY, raw)
            return {"hmac": ubinascii.b2a_base64(mac).decode().strip()}
        except:
            return {"error": "hmac failed"}

    # ---------------------
    # Keypart（AES）提供
    # ---------------------
    if cmd == "keypart":
        return {
            "keypart": ubinascii.b2a_base64(SECRET_AES_KEYPART).decode().strip()
        }

    # ---------------------
    # 情報取得
    # ---------------------
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

    return {"error": "unknown cmd"}

# =========================================================
#  メインループ
# =========================================================
while True:
    line = sys.stdin.readline()

    if not line:
        continue

    flash_led()

    try:
        obj = ujson.loads(line.strip())
    except:
        continue  # JSON構文エラー → 無視

    resp = process_request(obj)
    print(ujson.dumps(resp))

