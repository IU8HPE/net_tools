# 🧭 Network Tools – Dark Blue Edition

**Network Tools** is a standalone desktop application written in **Python + Tkinter**, featuring a sleek dark-blue interface.  
It provides a complete suite of **IP and CIDR utilities** for IPv4 and IPv6 — fully offline, with zero external dependencies.

---

## 🚀 Features

### 🧩 CIDR → IP Range
- Calculate **network**, **broadcast**, **netmask**, **wildcard**, **first/last IP**, and **usable hosts**.  
- Display binary formats for all key addresses.  
- IPv4 and IPv6 supported.

### 🔁 IP Range → CIDR
- Convert any IP range into a minimal list of CIDR blocks.  
- Shows total number of addresses covered.

### 🧮 CIDR Aggregation
- Merge overlapping or adjacent networks automatically.  
- Ideal for routing table optimization.

### 🧱 Subnetter / Supernetter
- Split a network into smaller subnets (by prefix).  
- Expand a network to a larger supernet if possible.

### ⚙️ IP Utilities
- Convert **IP ↔ Integer**  
- Display **binary representation**  
- Perform **reverse DNS lookup (PTR)**  

---

## 💻 Technical Info

| Item | Detail |
|------|--------|
| **Language** | Python 3 (3.10+) |
| **GUI Framework** | Tkinter (custom dark-blue theme) |
| **External Dependencies** | None |
| **Platforms** | Windows, macOS, Linux |
| **Build System** | PyInstaller (`--onefile --noconsole`) |
| **Offline Use** | ✅ Yes |
| **IPv6 Support** | ✅ Full |

---

## 🏗️ Build Instructions (Windows)

1. Install **PyInstaller**:
   ```bash
   py -3 -m pip install pyinstaller



