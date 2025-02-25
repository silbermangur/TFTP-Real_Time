# TFTP-Real_Time

# TFTP-Immplmention
# UDP File Transfer System with TFTP Compatibility

## 📌 Project Overview
This project implements a **UDP-based file transfer system**, inspired by **TFTP**, but with **added security and reliability features**.

## ✨ Features
- 📡 **UDP File Transfer Protocol**
- 🔐 **AES Encryption** for secure transfers
- ✅ **File Integrity Check (MD5)**
- 📂 **Backup & Recovery System**
- 📡 **TFTP RRQ (Read Request) Support**
- 📡 **TFTP WRQ (Write Request) supported**
- 🔄 **Packet Acknowledgment & Retransmission**
- 🛠 **Error Handling (Missing Files, Disk Full, etc.)**

---

## ⚙️ **Installation**
### **1️⃣ Install Required Dependencies**
```sh
sudo apt update && sudo apt install -y gcc openssl libssl-dev

2️⃣ Compile the Server and Client
gcc -o server server.c encrypt.c -lssl -lcrypto
gcc -o client client.c encrypt.c -lssl -lcrypto

Name: Gur Silberman
