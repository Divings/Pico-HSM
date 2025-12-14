import ujson
# =========================================================
#  Profile support（追加）
# =========================================================
PROFILE_FILE = "profile.json"

# ---- プロファイル読込（未登録なら None） ----
def load_profile():
    try:
        with open(PROFILE_FILE, "r") as f:
            return ujson.load(f)
    except:
        return None

# ---- プロファイル保存（PC側から一度だけ） ----
def save_profile(device_name, device_type, usage):
    # 既に登録済みなら拒否
    if load_profile() is not None:
        return False

    profile = {
        "device_name": device_name,
        "device_type": device_type,   # "personal" / "corporate"
        "device_id": DEVICE_ID,       # 既存の DEVICE_ID を使用
        "usage": usage,
        "created_at": int(time.time())
    }

    with open(PROFILE_FILE, "w") as f:
        ujson.dump(profile, f)

    return True
