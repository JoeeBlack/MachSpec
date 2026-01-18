# MachSpec - XPC Fuzzer & Capability Mapper

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Swift](https://img.shields.io/badge/Swift-5.5%2B-orange)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Research_Prototype-yellow)

**MachSpec** is a comprehensive research framework designed for identifying vulnerabilities in macOS XPC services. It automates the process of service enumeration, interface profiling, coverage-guided fuzzing, and authentication testing.

## 🚀 Features

*   **🔍 Service Enumerator**: Automatically crawls `/System/Library/Launch*` and `/Library/Launch*` to discover XPC services, parsing `plist` files to extract binary paths, entitlements, and code signing requirements.
*   **🧠 Interface Profiler**:
    *   **Static**: Extracts strings and symbols to heuristically identify potential XPC dictionary keys.
    *   **Dynamic**: Uses **Frida** to intercept `xpc_connection_send_message` and trace real-time IPC traffic.
*   **💥 Fuzzer**:
    *   **Structure-Aware**: Generates valid, nested XPC dictionaries and arrays.
    *   **Mutation Engine**: Applies bit-flipping, integer overflows, type confusion, and boundary expansion.
    *   **Native Harness**: A compiled **Swift** client that bridges JSON payloads to raw `xpc_object_t` messages for high-performance fuzzing.
*   **🛡️ Auth Tester**: actively verifies if privileged services accept connections from unauthorized (entitlement-less) clients.
*   **📊 Reporting**: Exports capability maps and vulnerability findings to JSON.

## 🛠️ Installation

### Prerequisites
*   **macOS** 11.0 or later (Big Sur+).
*   **Python** 3.10+.
*   **Swift** (included with Xcode Command Line Tools).
*   **Frida**: For dynamic profiling (`pip install frida-tools`).

### Setup

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/yourusername/machspec.git
    cd machspec
    ```

2.  **Set up Virtual Environment**:
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

3.  **Install Python dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

4.  **Compile the Native Helper**:
    The Swift client is required for sending fuzzed messages.
    ```bash
    cd machspec/native/XPCClient
    swift build -c release
    ```
    *The binary will be built at `.build/release/XPCClient`.*

## 📖 Usage

All commands are run via the python module `machspec.machspec.main`.

### 1. Build the Service Database
First, scan your system to discover available XPC services.
```bash
python3 -m machspec.machspec.main enumerate
```

### 2. View Discovered Services
List services found in the database.
```bash
python3 -m machspec.machspec.main list-services
```

### 3. Fuzzing a Service
Target a specific Mach service name. The fuzzer will generate random XPC dictionaries and attempt to crash the target.
```bash
# Example: Fuzzing the User Activity Daemon
python3 -m machspec.machspec.main fuzz com.apple.coreservices.lsuseractivityd --iterations 1000
```
> **⚠️ Warning**: Fuzzing system services can cause instability, log spam, or data loss. **Always run inside a Virtual Machine.**

### 4. Authentication Testing
Check if a hidden or privileged service allows connections from our unprivileged client.
```bash
python3 -m machspec.machspec.main auth-test com.apple.coreservices.lsuseractivityd
```

### 5. Dynamic Profiling (Frida)
Trace XPC messages sent by a binary or service in real-time.
```bash
# Spawn and trace a binary
python3 -m machspec.machspec.main profile /System/Library/CoreServices/Finder.app/Contents/MacOS/Finder

# Attach to a running process name
python3 -m machspec.machspec.main profile "Dock" --no-spawn
```
*(Note: profiling system binaries usually requires disabling SIP)*

## 🏗️ Architecture

```mermaid
graph TD
    A[CLI / Controller (Python)] -->|Fuzzing| B[Native Client (Swift)]
    A -->|Profiling| C[Frida Agent (JS)]
    A -->|Enumerate| D[SQLite Database]
    B -->|xpc_connection| E[Target XPC Service]
    C -->|Interceptor| E
```

- **Python Layer**: Orchestration, Database Management, Generation Logic.
- **Swift Layer**: Low-level `xpc_object_t` creation and Mach message sending.
- **Frida Layer**: Dynamic instrumentation for protocol reverse engineering.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is for **educational and security research purposes only**. Do not use this tool on systems you do not own or have explicit permission to test.
