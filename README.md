# EZInjector 🚀

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11%20(x64)-0078d7.svg)]()
[![Language](https://img.shields.io/badge/Language-C%2B%2B17-00599C.svg)]()
[![UI](https://img.shields.io/badge/UI-ImGui%20%2B%20DirectX11-purple.svg)]()

**EZInjector** is a modern, modular, and highly extensible dynamic link library (DLL) injection framework for Windows x64. Built with a sleek modern user interface powered by **Dear ImGui** and **DirectX 11**, it provides robust payload delivery mechanisms ranging from standard API calls to stealthy manual mapping.

---

## ✨ Features

- **🎨 Modern & Minimalist UI**: Sleek dark-themed interface crafted with ImGui and DirectX 11.
- **⚡ Drag & Drop Support**: Seamlessly queue multiple `.dll` payloads by dropping them directly into the window.
- **🎯 Flexible Target Selection**: Inject into already running processes or launch new executables in a suspended state.
- **🧱 Modular OOP Architecture**: Clean, extensible interface (`IInjector`) designed for painless implementation of custom injection algorithms.
- **🛡️ Advanced Stealth Options**:
  - **PEB Unlinking**: Removes module entries from `InLoadOrder`, `InMemoryOrder`, and `InInitializationOrder` lists.
  - **PE Header Erasure**: Wipes DOS and NT headers from remote memory after injection.
  - **Thread Hijacking**: Avoids `CreateRemoteThread` detection by hijacking existing process threads.
  - **Memory Concealment**: Adjusts section memory protections to mimic legitimate allocations.

---

## 💉 Injection Methods

### 1. LoadLibrary (Standard & Hijack)
- **Standard**: Allocates remote memory and spawns a thread targeting `LoadLibraryA`.
- **Thread Hijacking**: Suspends an active thread in the target process, modifies the execution context (`RIP`) to execute a custom assembly routine calling `LoadLibraryA`, and cleanly restores execution.

### 2. Manual Mapping
Custom PE loader that bypasses Windows loader routines entirely:
- Allocates memory in the target process.
- Resolves Base Relocations (`DIR64`, `HIGHLOW`).
- Resolves Import Address Tables (IAT).
- Executes TLS Callbacks.
- Registers Exception Handlers (`RtlAddFunctionTable`).
- Invokes `DllMain` remotely via shellcode.

---

## 🏗️ Architecture & Roadmap

EZInjector underwent a comprehensive architectural refactoring to transition from a monolithic codebase into decoupled design layers:

```text
EZInjector/
├── src/
│   ├── Injection/    # Core injection interfaces & implementations (IInjector)
│   ├── UI/           # ImGui window management & DirectX 11 renderer
│   ├── Utils/        # NT structures, process enumeration, memory manipulation
│   └── main.cpp      # Application entry point
```

### 🔮 Roadmap (Upcoming Kernel Injections)
Thanks to the polymorphic `IInjector` design, kernel-mode payloads will be introduced in future updates:
- [ ] **Kernel Native Inject**: Ring-0 APC queuing and shellcode delivery via kernel driver.
- [ ] **Kernel Manual Map**: Undetected kernel-level PE mapping directly into user-mode EPROCESS address spaces.

---

## 🛠️ Build Instructions

### Requirements
- **OS**: Windows 10 / 11 (x64)
- **IDE**: Microsoft Visual Studio 2022 (with Desktop development with C++)
- **Windows SDK**: 10.0 or later

### Compiling from Source
1. Clone the repository:
   ```bash
   git clone https://github.com/awln64/EZInjector.git
   cd EZInjector
   ```
2. Open `EZInjector.sln` in Visual Studio 2022.
3. Select the **Release | x64** build configuration.
4. Build the solution (`Ctrl + Shift + B`).
5. The compiled binary will be generated in `x64/Release/EZInjector.exe`.

---

## 📄 License & Attribution

This project is licensed under the **Apache License 2.0**. See the [NOTICE](NOTICE) file for third-party software attributions and details.

Disclaimer: *This tool is developed strictly for educational purposes, software analysis, and legitimate reverse engineering. The authors assume no liability for misuse.*
