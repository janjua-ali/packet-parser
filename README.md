# HTTP Packet Parser & Alert System (NIDS-like Project)

**Author:** Ali Noor  
**Email:** an2345001@gmail.com  
**Type:** Internship Project  

---

## 📌 Overview
This project is a simplified **Network Intrusion Detection System (NIDS)** implemented in **C++**.  
It captures HTTP packets, parses requests, applies detection rules, and generates alerts for suspicious activity.

**Main objectives:**
- Capture raw HTTP traffic
- Parse HTTP requests (method, headers, body, etc.)
- Match against rule-based signatures
- Log alerts to console and file

---

## ⚡ Features
- Raw packet capture with socket/pcap support  
- HTTP filtering only (ignores other protocols)  
- Rule engine (regex / substring)  
- Console + log alerts (`~/nids_output.log`)  
- Testable with `curl` requests  

---

## 🛠️ Requirements
- Linux (tested on Ubuntu)  
- `g++` (C++17 or later)  
- `make` (optional)  
- `sudo` (for raw packet capture)  
- `curl` (for testing)  

---

## 🔧 Build
Compile with:
```bash
g++ -std=c++17 -O2 -o nids src/*.cpp
