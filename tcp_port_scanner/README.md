# 🔍 TCP Port Scanner — C++ Edition

Tool jaringan untuk melakukan **TCP port scanning** secara cepat menggunakan multi-threading, ditulis murni dalam **C++** untuk Windows.

---

## ✨ Fitur

| Fitur | Keterangan |
|---|---|
| 🚀 **Multi-Threading** | Hingga 500 thread paralel |
| 🎯 **Banner Grabbing** | Deteksi service banner otomatis |
| 🗺️ **Service Detection** | Database 60+ layanan umum |
| 📊 **Progress Bar** | Real-time progress scanning |
| 🎨 **Color Output** | Output berwarna di terminal |
| 💾 **Export File** | Simpan hasil ke `.txt` |
| ⏱️ **Latency** | Ukur response time tiap port |
| 🔀 **Flexible Port Spec** | Range, list, dan kombinasi |

---

## 🛠️ Kompilasi

### Requirement
- **Compiler:** MinGW-w64 (g++) atau TDM-GCC
- **OS:** Windows 7/10/11
- **Library:** Winsock2 (sudah built-in di Windows)

### Cara Compile (Otomatis)
```batch
build.bat
```

### Cara Compile (Manual)
```bash
g++ -o port_scanner.exe port_scanner.cpp -lws2_32 -std=c++17 -O2
```

---

## 🚀 Penggunaan

```
port_scanner.exe <target> [options]
```

### Options

| Flag | Deskripsi | Default |
|------|-----------|---------|
| `-p <ports>` | Spesifikasi port | `1-1024` |
| `-t <num>` | Jumlah thread | `100` |
| `-T <ms>` | Timeout (milliseconds) | `2000` |
| `-o <file>` | Simpan hasil ke file | - |
| `-v` | Verbose (tampilkan port tertutup) | off |
| `-nb` | Nonaktifkan banner grabbing | off |
| `-h` | Tampilkan bantuan | - |

### Format Port (`-p`)

| Format | Contoh | Keterangan |
|--------|--------|------------|
| Single | `-p 80` | Satu port |
| Range | `-p 1-1024` | Port 1 hingga 1024 |
| List | `-p 80,443,22` | Port tertentu |
| Mixed | `-p 1-100,443,8000-9000` | Kombinasi |

---

## 💡 Contoh Penggunaan

```bash
# Scan port default (1-1024) di localhost
port_scanner.exe 127.0.0.1

# Scan semua port di IP lokal
port_scanner.exe 192.168.1.1 -p 1-65535 -t 500

# Scan port tertentu
port_scanner.exe 192.168.1.1 -p 80,443,22,3306,8080

# Scan dengan timeout cepat dan simpan hasil
port_scanner.exe 10.0.0.1 -p 1-10000 -t 300 -T 1000 -o hasil_scan.txt

# Scan domain + verbose (tampilkan port tertutup juga)
port_scanner.exe scanme.nmap.org -p 1-100 -v

# Tanpa banner grabbing (lebih cepat)
port_scanner.exe 192.168.1.1 -p 1-65535 -nb -t 500
```

---

## 📋 Contoh Output

```
  ████████╗ ██████╗██████╗     ...
  [ TCP Port Scanner v1.0 | C++ Edition ]

  [*] Resolving target: 192.168.1.1 ... 192.168.1.1
  [*] Scan started    : 2024-01-15 20:30:00
  [*] Ports to scan   : 1024 (1-1024)
  [*] Threads         : 100

  PORT        SERVICE         LATENCY   BANNER
  ─────────────────────────────────────────────────────────────
  [OPEN]    22/tcp    SSH             15ms      SSH-2.0-OpenSSH_8.9
  [OPEN]    80/tcp    HTTP            8ms       HTTP/1.1 200 OK Server: nginx
  [OPEN]    443/tcp   HTTPS           12ms
  [OPEN]    3306/tcp  MySQL           5ms

  ╔══════════════  SCAN SUMMARY  ══════════════╗
  ║  Target       :  192.168.1.1              ║
  ║  Ports Scanned:  1024                     ║
  ║  Open Ports   :  4                        ║
  ║  Duration     :  3.521 seconds            ║
  ╚════════════════════════════════════════════╝
```

---

## ⚠️ Disclaimer

Tool ini dibuat untuk tujuan **edukasi dan testing jaringan sendiri**. Penggunaan untuk melakukan scanning pada jaringan/host tanpa izin adalah **ilegal**. Gunakan secara bertanggung jawab.

---

## 📁 Struktur File

```
tcp_port_scanner/
├── port_scanner.cpp    # Source code utama
├── build.bat           # Script compile Windows
└── README.md           # Dokumentasi ini
```
