# SecureShare

> LAN-based encrypted file sharing system built in C++20 with Qt6 GUI

![C++](https://img.shields.io/badge/C++-20-blue.svg)
![Qt](https://img.shields.io/badge/Qt-6.10.2-green.svg)
![OpenSSL](https://img.shields.io/badge/OpenSSL-3.6.2-red.svg)
![SQLite](https://img.shields.io/badge/SQLite-3.46.1-lightgrey.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)
![Platform](https://img.shields.io/badge/Platform-Linux-orange.svg)

## Overview

SecureShare is a multi-user LAN file sharing system with end-to-end encryption, built entirely from scratch in C++20. Every file is encrypted with AES-256-CBC before being stored. Every connection runs on its own thread. Every upload passes through a 5-layer security scanner.

Built as an Operating Systems Lab project — but engineered like a real system.

---

## Features

- **AES-256-CBC Encryption** — all files encrypted at rest using OpenSSL EVP
- **SHA-256 Authentication** — passwords never stored in plaintext
- **Session Token Auth** — token validated on every request server-side
- **5-Layer Security Scanner** — extension filter, size limit, malware signatures, binary detection, injection prevention
- **Unix chmod-style Permissions** — Owner / Read-Only / No Access per file per user
- **User-to-User File Sharing** — share files with any registered user
- **Activity Log** — timestamped audit trail of all operations
- **100 MB File Limit** — enforced server-side before encryption
- **Qt6 Dark GUI** — 4-tab professional interface
- **Multithreaded Server** — dedicated thread per client, semaphore-limited to 10 concurrent connections
- **Persistent Storage** — SQLite3 database survives restarts

---

## OS Concepts Implemented

| Concept | Implementation |
|---|---|
| Multithreading | `std::thread` per client connection |
| Counting Semaphore | `counting_semaphore<10>` — max concurrent connections |
| Mutex | `std::mutex` + `lock_guard` on all DB writes |
| IPC via Sockets | POSIX TCP sockets on port 8080 |
| File I/O | SQLite3 with prepared statements |

---

## Tech Stack

- **Language:** C++20
- **GUI:** Qt6 Widgets
- **Crypto:** OpenSSL (AES-256-CBC, SHA-256)
- **Database:** SQLite3
- **Build:** CMake 4.3.1 + Ninja
- **Platform:** Kali Linux / Ubuntu

---

## Project Structure
SecureShare/
├── src/
│   ├── server/      # TCP server, threading, semaphore, command parser
│   ├── client/      # CLI client
│   ├── gui/         # Qt6 graphical interface
│   ├── auth/        # SHA-256 authentication module
│   ├── crypto/      # AES-256 encryption module
│   └── storage/     # SQLite3 storage module
├── include/         # Header files
├── build/           # CMake build directory
└── CMakeLists.txt

---

## Build & Run

### Prerequisites

```bash
sudo apt install build-essential cmake ninja-build libssl-dev libsqlite3-dev qt6-base-dev
```

### Build

```bash
mkdir -p build && cd build
cmake .. -G Ninja
ninja
```

### Run

```bash
# Terminal 1 — start server
./src/server/server

# Terminal 2 — start GUI
export DISPLAY=:0 && ./src/gui/gui
```

---

## Screenshots

> Add screenshots here

---


## License

MIT License — see [LICENSE](LICENSE) for details.

---

> Operating Systems Lab Project — May 2026
