import serial
import serial.tools.list_ports
import json
import time

# ==============================
# Pico 自動検出
# ==============================
def find_pico_port():
    ports = serial.tools.list_ports.comports()
    for p in ports:
        name = (p.description or "").lower()
        if (
            "pico" in name or
            "micropython" in name or
            "usb serial device" in name or
            "raspberry" in name or
            "cdc" in name or
            p.vid == 0x2E8A  # Raspberry Pi公式VID
        ):
            return p.device
    return None


def connect_pico():
    port = find_pico_port()
    if port is None:
        raise RuntimeError("Pico HSM が見つかりませんでした")

    print(f"[INFO] Pico HSM found at {port}")
    ser = serial.Serial(port, 115200, timeout=1)
    time.sleep(2)  # Pico起動待ち
    return ser


# ==============================
# JSON送受信（タイムアウト付き）
# ==============================
def send_cmd(ser, obj, timeout=3):
    ser.write((json.dumps(obj) + "\n").encode())

    start = time.time()
    while time.time() - start < timeout:
        line = ser.readline().decode(errors="ignore").strip()
        if not line:
            continue
        try:
            data = json.loads(line)

            # USB自己エコー対策（送信JSONそのものは無視）
            if data == obj:
                continue

            return data  # None / dict をそのまま返す
        except:
            continue

    return None  # タイムアウト


# ==============================
# メイン処理
# ==============================
def main():
    ser = connect_pico()

    # ---- プロファイル確認 ----
    print("\n[1] プロファイル確認")
    profile = send_cmd(ser, {"cmd": "get_profile"})

    if profile:
        print("[INFO] すでに登録済みです")
        print(json.dumps(profile, indent=2, ensure_ascii=False))
        return

    print("[INFO] 未登録のためセットアップを開始します\n")

    # ---- ユーザー入力 ----
    device_name = input("端末名 (例: Anvelk-PicoHSM-01): ").strip()

    while True:
        device_type = input("種別 (personal / corporate): ").strip().lower()
        if device_type in ("personal", "corporate"):
            break
        print("  ※ personal か corporate を入力してください")

    usage = input("用途 (例: EncryptSecureDEC Key Storage): ").strip()

    # ---- 登録 ----
    print("\n[2] プロファイル登録中...")
    resp = send_cmd(ser, {
        "cmd": "set_profile",
        "data": {
            "device_name": device_name,
            "device_type": device_type,
            "usage": usage
        }
    })

    if not resp or resp.get("status") != "ok":
        print("[ERROR] 登録に失敗しました:", resp)
        return

    print("[OK] 登録完了")

    # ---- 再確認 ----
    print("\n[3] 登録内容確認")
    profile = send_cmd(ser, {"cmd": "get_profile"})
    print(json.dumps(profile, indent=2, ensure_ascii=False))


# ==============================
# エントリポイント
# ==============================
if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("[ERROR]", e)
    finally:
        input("\nEnterキーで終了")
