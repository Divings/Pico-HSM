    # ---------------------
    # Profile
    # ---------------------
    if cmd == "get_profile":
        return load_profile()  # 未登録なら None

    if cmd == "set_profile":
        data = obj.get("data", {})
        ok = save_profile(
            data.get("device_name"),
            data.get("device_type"),
            data.get("usage")
        )
        return {"status": "ok" if ok else "already_registered"}
