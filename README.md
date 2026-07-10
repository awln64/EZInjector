# EZInjector 🚀

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11%20(x64)-0078d7.svg)]()
[![Language](https://img.shields.io/badge/Language-C%2B%2B17-00599C.svg)]()
[![UI](https://img.shields.io/badge/UI-ImGui%20%2B%20DirectX11-purple.svg)]()

**EZInjector** is a modern, modular, and highly extensible dynamic link library (DLL) injection framework for Windows x64. Built with a sleek modern user interface powered by **Dear ImGui** and **DirectX 11**, it provides robust payload delivery mechanisms ranging from standard API calls to stealthy kernel-level manual mapping.

---

## ✨ Features

- **🎯 Flexible Target Selection**: Inject into already running processes or launch new executables in a suspended state.
- **🧱 Modular OOP Architecture**: Clean, extensible interface (`IInjector`) designed for painless implementation of custom injection algorithms.
- **💉 4 Injection Methods**: From simple `LoadLibraryA` calls to full kernel-mode manual mapping — choose the right method for the task.
- **🔧 Kernel Driver (EZInjectorKernel)**: Custom kernel driver (`EZInjectorKernel.sys`) for Ring-0 injection that bypasses user-mode API hooks and monitoring.
- **🛡️ Advanced Stealth Options**:
  - **PEB Unlinking**: Removes module entries from `InLoadOrder`, `InMemoryOrder`, and `InInitializationOrder` lists.
  - **PE Header Erasure**: Wipes DOS and NT headers from remote memory after injection.
  - **Thread Hijacking**: Avoids `CreateRemoteThread` detection by hijacking existing process threads.
  - **Memory Concealment**: Adjusts section memory protections to mimic legitimate allocations.
  - **Minimal Access Rights**: Uses least-privilege `OpenProcess` flags instead of `PROCESS_ALL_ACCESS`.
  - **RW → RX Memory Transitions**: Avoids suspicious `PAGE_EXECUTE_READWRITE` allocations.

---

## 💉 Injection Methods

### 1. LoadLibrary (Standard & Hijack)
Standard user-mode injection via the Windows loader:
- **Standard**: Allocates remote memory, writes the DLL path, and spawns a thread targeting `LoadLibraryA`.
- **Thread Hijacking**: Suspends an active thread in the target process, modifies the execution context (`RIP`) to execute a custom x64 assembly stub calling `LoadLibraryA`, and cleanly restores execution — avoiding `CreateRemoteThread` entirely.

### 2. Manual Mapping
Custom user-mode PE loader that bypasses Windows loader routines entirely:
- Allocates memory in the target process.
- Resolves Base Relocations (`DIR64`, `HIGHLOW`).
- Resolves Import Address Tables (IAT).
- Executes TLS Callbacks.
- Registers Exception Handlers (`RtlAddFunctionTable`).
- Invokes `DllMain` remotely via position-independent shellcode.

### 3. Kernel Native Inject
Ring-0 injection via the `EZInjectorKernel.sys` driver:
- Communicates with the kernel driver through `DeviceIoControl` (IOCTL).
- The driver attaches to the target process (`KeStackAttachProcess`), resolves `LoadLibraryA` from the remote PEB, and spawns a user-mode thread via APC queuing to load the DLL.
- Bypasses user-mode API hooks and monitoring since the injection originates from kernel space.

### 4. Kernel Manual Map
Full kernel-mode PE loader — the stealthiest method:
- The driver reads the DLL file from disk using kernel file I/O (`ZwCreateFile` / `ZwReadFile`).
- Attaches to the target process address space and performs a complete PE mapping: section copying, base relocation patching, and IAT resolution — all from Ring-0.
- Deploys a user-mode loader stub that handles `DllMain` invocation, TLS callbacks, and exception handler registration.
- The DLL never touches the Windows loader — no `LdrLoadDll`, no loader lock, no `LoadLibrary` calls.

---

## 🏗️ Architecture

EZInjector is split into a user-mode application and a kernel driver:

```text
EZInjector/
├── src/
│   ├── Injection/         # Core injection interfaces & implementations (IInjector)
│   ├── UI/                # ImGui window management & DirectX 11 renderer
│   ├── Utils/             # NT structures, process enumeration, memory manipulation
│   └── main.cpp           # Application entry point
├── EZInjectorKernel/
│   ├── Driver.c           # Kernel driver: IOCTL dispatch, native inject, manual map
│   ├── PeUtils.c          # Kernel PE parser: exports, PEB walking, module resolution
│   └── Logger.c           # Kernel debug logging (stripped in Release)
```

---

## 🛠️ Build Instructions

### Requirements
- **OS**: Windows 10 / 11 (x64)
- **IDE**: Microsoft Visual Studio 2022 (with Desktop development with C++)
- **Windows SDK**: 10.0 or later
- **WDK**: Windows Driver Kit (for building `EZInjectorKernel.sys`)

### Compiling from Source
1. Clone the repository:
   ```bash
   git clone https://github.com/awln64/EZInjector.git
   cd EZInjector
   ```
2. Open `EZInjector.sln` in Visual Studio 2022.
3. Select the **Release | x64** build configuration.
4. Build the solution (`Ctrl + Shift + B`).
5. The compiled binaries will be generated in:
   - `x64/Release/EZInjector.exe` — User-mode injector
   - `EZInjectorKernel/x64/Release/EZInjectorKernel.sys` — Kernel driver

> **Note**: The kernel driver must be loaded separately (e.g. via `sc create` + `sc start`) before using kernel injection methods. EZInjector connects to the driver automatically if it's already running.

---

## 📄 License & Attribution

This project is licensed under the **Apache License 2.0**. See the [NOTICE](NOTICE) file for third-party software attributions and details.

Disclaimer: *This tool is developed strictly for educational purposes, software analysis, and legitimate reverse engineering. The authors assume no liability for misuse.*
