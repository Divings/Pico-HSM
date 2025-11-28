# Raspberry Pi Pico W – Hardware Security Module (HSM)

Author: Tomoya Koga (古賀智也)  
Organization: Anvelk Innovations LLC / Innovation Craft Inc.  
License: MIT

---

## 🔐 Overview

This project implements a lightweight Hardware Security Module (HSM)
using **Raspberry Pi Pico W**.

It provides secure key derivation, encrypted storage, AES/RSA operations,
and optional Wi-Fi/BLE connectivity designed for embedded or desktop
client applications.

---

## ✨ Features

- **Device-bound key derivation** using `unique_id()`
- **MASTER_SEED** stored safely on the device
- **AES-GCM encryption / RSA key pairs**
- **Wi-Fi communication** (REST API or custom protocol)
- **BLE communication** (optional)
- **Automatic low-power sleep** after inactivity
- **BootSel-based physical reboot**
- **LED indicators** for status and operations
- **Python / CLI / Web clients included**

---

## 📂 Directory Structure

