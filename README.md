# MachSpec 🕵️‍♂️🍏

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python&logoColor=white)
![Swift](https://img.shields.io/badge/Swift-5.5%2B-orange?style=for-the-badge&logo=swift&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-macOS-lightgrey?style=for-the-badge&logo=apple&logoColor=black)

**MachSpec** is a specialized research tool built to uncover security vulnerabilities in macOS XPC services. It bridges the gap between static analysis and dynamic fuzzing to help researchers secure the macOS IPC landscape.

---

## 🧐 Why MachSpec?

XPC (Cross-Process Communication) is the backbone of macOS inter-process communication. Thousands of system services use it to communicate, often with high privileges (root).

**The Problem:** Identifying which services are vulnerable to unauthorized connections or malformed inputs is a manual, tedious process.
**The Solution:** MachSpec automates the lifecycle of XPC vulnerability research:
1.  **Discovery**: Finds hidden services.
2.  **Access Check**: Verifies if unprivileged users can connect.
3.  **Stress Test**: Bombards the service with valid and invalid data to find crashes (fuzzing).

## 🧠 How It Works (The Logic)

MachSpec operates in a logical loop to map and test the system:

```mermaid
graph LR
    A[🔎 Enumerate] -->|Build Database| B[🛡️ Analyze]
    B -->|Check Auth| C[⚡ Fuzz]
    C -->|Monitor Crashes| D[📊 Report]
```

1.  **Enumerator**: Scans `/System/Library/LaunchDaemons` and other paths to build a database of all available XPC services, parsing their `plist` files for binary paths and entitlements.
2.  **Profiler**: Analyzes the binary to guess what kind of messages it expects (Dictionary keys, arrays, etc.).
3.  **Fuzzer**:
    *   Generates complex XPC messages (Dictionaries, Arrays, UUIDs, etc.).
    *   Mutates them (Bit flips, buffer overflows, type confusion).
    *   Sends them to the target service using a **Native Swift Client**.
4.  **Monitor**: Uses **Frida** to trace messages and detect crashes in real-time.

## 🚀 Getting Started

### Prerequisites
*   **macOS** (Big Sur or newer)
*   **Python 3.10+**
*   **Xcode Command Line Tools** (for Swift)

### Installation

1.  **Clone & Setup**:
    ```bash
    git clone https://github.com/yourusername/machspec.git
    cd machspec
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    ```

2.  **Compile Native Helper**:
    The fuzzer needs a native Swift binary to talk to XPC.
    ```bash
    cd machspec/native/XPCClient
    swift build -c release
    ```
    *Note: This creates the binary at `.build/release/XPCClient`.*

## 🎮 Usage

All commands use the main Python entry point.

### 1. Build the Service Map
Before testing, you need to know what's running.
```bash
python3 -m machspec.machspec.main enumerate
```

### 2. Pick a Target
List all found services to choose a victim.
```bash
python3 -m machspec.machspec.main list-services
```

### 3. Test for Vulnerabilities (Fuzzing)
Send random data to a service to see if it breaks.
```bash
# Syntax: fuzz <service_name> --iterations <count>
python3 -m machspec.machspec.main fuzz com.apple.coreservices.lsuseractivityd --iterations 500
```

### 4. Check Permissions (Auth Test)
Can a normal user talk to this root service?
```bash
python3 -m machspec.machspec.main auth-test com.apple.coreservices.lsuseractivityd
```

### 5. Export Results
Get a JSON report of your findings.
```bash
python3 -m machspec.machspec.main export-report
```

## ⚠️ Disclaimer

**Research Tool Only.**
This tool is designed for security professionals and researchers. Fuzzing system services **can and will crash system components**, potentially leading to data loss or system instability.
*   **Always** run in a Virtual Machine.
*   **Do not** run on production systems.

## 📄 License

MIT License. See [LICENSE](LICENSE) for details.
