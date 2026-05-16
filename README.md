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
<img width="638" height="388" alt="Screenshot 2026-05-16 114420" src="https://github.com/user-attachments/assets/2e31e047-bf91-4b9b-af96-422931c171e1" />
<img width="631" height="391" alt="Screenshot 2026-05-16 114653" src="https://github.com/user-attachments/assets/81e68480-ac94-4029-847b-58c0279e7cc6" />
<img width="620" height="372" alt="Screenshot 2026-05-16 115653" src="https://github.com/user-attachments/assets/b2cce757-36ee-480b-9fc1-3e1098c0b464" />
<img width="628" height="342" alt="Screenshot 2026-05-16 115456" src="https://github.com/user-attachments/assets/830eead0-e884-4448-8104-e92bf626063c" />
<img width="613" height="347" alt="Screenshot 2026-05-16 115434" src="https://github.com/user-attachments/assets/31a70e5a-9908-480a-a854-e0342c70b742" />

---


## License

MIT License — see [LICENSE](LICENSE) for details.

---

> Operating Systems Lab Project — May 2026
