#include "LoadLibraryInjector.h"
#include "../Utils/ProcessUtils.h"
#include "../Utils/MemoryUtils.h"

#ifndef _WIN64
#error "LoadLibraryInjector shellcode is x64-only. Build for x64 platform."
#endif

namespace Injection {

    LoadLibraryInjector::LoadLibraryInjector(const Options& options) : m_options(options) {}

    InjectionResult LoadLibraryInjector::Inject(DWORD pid, const std::string& dllPath) {
        if (m_options.threadHijack) {
            return Inject_ThreadHijack(pid, dllPath);
        } else {
            return Inject_LoadLibrary(pid, dllPath);
        }
    }

    InjectionResult LoadLibraryInjector::Inject_LoadLibrary(DWORD pid, const std::string& dllPath) {
        HANDLE hProcess = OpenProcess(
            PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ |
            PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION,
            FALSE, pid);
        if (!hProcess) {
            DWORD err = GetLastError();
            return InjectionResult::Failure("Failed to open target process.", err);
        }
        
        size_t pathLen = dllPath.length() + 1;
        void* pAllocatedMem = VirtualAllocEx(hProcess, nullptr, pathLen, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

        if (!pAllocatedMem) {
            DWORD err = GetLastError();
            CloseHandle(hProcess);
            return InjectionResult::Failure("VirtualAllocEx failed in target process.", err);
        }
        
        WriteProcessMemory(hProcess, pAllocatedMem, dllPath.c_str(), pathLen, nullptr);
        
        FARPROC pLoadLibrary = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
        HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)pLoadLibrary, pAllocatedMem, 0, nullptr);
        
        if (!hThread) {
            DWORD err = GetLastError();
            VirtualFreeEx(hProcess, pAllocatedMem, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return InjectionResult::Failure("CreateRemoteThread failed to spawn remote thread.", err);
        }
        
        DWORD waitResult = WaitForSingleObject(hThread, 30000);
        if (waitResult == WAIT_TIMEOUT) {
            TerminateThread(hThread, 0);
            VirtualFreeEx(hProcess, pAllocatedMem, 0, MEM_RELEASE);
            CloseHandle(hThread);
            CloseHandle(hProcess);
            return InjectionResult::Failure("Remote LoadLibraryA thread timed out after 30 seconds.");
        }
        
        DWORD exitCode = 0;
        GetExitCodeThread(hThread, &exitCode);
        DWORD_PTR hInjectedModule = (DWORD_PTR)exitCode;
        
        if (hInjectedModule == 0) {
            VirtualFreeEx(hProcess, pAllocatedMem, 0, MEM_RELEASE);
            CloseHandle(hThread);
            CloseHandle(hProcess);
            return InjectionResult::Failure("LoadLibraryA returned NULL inside target process. DLL failed to load or initialize.");
        }

        if (m_options.erasePe && hInjectedModule != 0) {
            Utils::ErasePEHeaders(hProcess, (HMODULE)hInjectedModule);
        }
        
        if (m_options.unlinkPeb && hInjectedModule != 0) {
            Utils::UnlinkModuleFromPEB(hProcess, (HMODULE)hInjectedModule);
        }
        
        VirtualFreeEx(hProcess, pAllocatedMem, 0, MEM_RELEASE);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        
        return InjectionResult::Success("Successfully injected via standard LoadLibraryA.");
    }

    InjectionResult LoadLibraryInjector::Inject_ThreadHijack(DWORD pid, const std::string& dllPath) {
        std::vector<DWORD> threadIds = Utils::GetTargetThreadIds(pid);

        if (threadIds.empty()) return InjectionResult::Failure("No threads found in target process for thread hijacking.");

        HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (!hProcess) {
            DWORD err = GetLastError();
            return InjectionResult::Failure("Failed to open target process.", err);
        }

        size_t pathLen = dllPath.length() + 1;
        size_t dataSize = 16; // 8 bytes HMODULE + 8 bytes status
        size_t shellcodeSize = 94;

        void* pMem = VirtualAllocEx(hProcess, nullptr, pathLen + dataSize + shellcodeSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (pMem == nullptr) {
            DWORD err = GetLastError();
            CloseHandle(hProcess);
            return InjectionResult::Failure("VirtualAllocEx failed in target process for thread hijacking.", err);
        }

        uintptr_t remotePathAddr = (uintptr_t)pMem;
        uintptr_t remoteDataAddr = remotePathAddr + pathLen;
        uintptr_t remoteShellcodeAddr = remoteDataAddr + dataSize;

        WriteProcessMemory(hProcess, (void*)remotePathAddr, dllPath.c_str(), pathLen, nullptr);

        FARPROC pLoadLibrary = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

        BYTE shellcode[] = {
            0x50,                                           // push rax
            0x51,                                           // push rcx
            0x52,                                           // push rdx
            0x41, 0x50,                                     // push r8
            0x41, 0x51,                                     // push r9
            0x41, 0x52,                                     // push r10
            0x41, 0x53,                                     // push r11
            0x9C,                                           // pushfq         ; save CPU flags
            0x48, 0x89, 0xE5,                               // mov rbp, rsp   ; backup current stack pointer
            0x48, 0x83, 0xE4, 0xF0,                         // and rsp, 0xFFFFFFFFFFFFFFF0
                                                            // align stack to 16 bytes (Win64 ABI)
            0x48, 0x83, 0xEC, 0x28,                         // sub rsp, 0x28  ; allocate shadow space
            0x48, 0xB9,                                     // mov rcx, <remotePathAddr>
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x48, 0xB8,                                     // mov rax, <pLoadLibrary>
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0xD0,                                     // call rax
            0x48, 0xB9,                                     // mov rcx, <remoteDataAddr>
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x48, 0x89, 0x01,                               // mov [rcx], rax
            0xC7, 0x41, 0x08, 0x01, 0x00, 0x00, 0x00,       // mov dword ptr [rcx+8], 1
            0x48, 0x89, 0xEC,                               // mov rsp, rbp     ; restore original stack pointer
            0x9D,                                           // popfq
            0x41, 0x5B,                                     // pop r11
            0x41, 0x5A,                                     // pop r10
            0x41, 0x59,                                     // pop r9
            0x41, 0x58,                                     // pop r8
            0x5A,                                           // pop rdx
            0x59,                                           // pop rcx
            0x58,                                           // pop rax
            0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,             // jmp qword ptr [rip+0]
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // placeholder: original Rip
        };

        memcpy(&shellcode[25], &remotePathAddr, sizeof(remotePathAddr));
        memcpy(&shellcode[35], &pLoadLibrary, sizeof(pLoadLibrary));
        memcpy(&shellcode[47], &remoteDataAddr, sizeof(remoteDataAddr));

        bool injected = false;
        DWORD_PTR hInjectedModule = 0;

        for (DWORD tid : threadIds) {
            HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, tid);
            if (!hThread)
                continue;

            if (SuspendThread(hThread) == (DWORD)-1) {
                CloseHandle(hThread);
                continue;
            }

            CONTEXT ctx;
            ctx.ContextFlags = CONTEXT_FULL;
            if (!GetThreadContext(hThread, &ctx)) {
                ResumeThread(hThread);
                CloseHandle(hThread);
                continue;
            }

            BYTE threadShellcode[94];
            memcpy(threadShellcode, shellcode, sizeof(shellcode));
            memcpy(&threadShellcode[86], &ctx.Rip, sizeof(ctx.Rip));

            ULONG64 zeroData[2] = { 0, 0 };
            WriteProcessMemory(hProcess, (void*)remoteDataAddr, zeroData, sizeof(zeroData), nullptr);
            WriteProcessMemory(hProcess, (void*)remoteShellcodeAddr, threadShellcode, sizeof(threadShellcode), nullptr);

            DWORD oldProtect;
            VirtualProtectEx(hProcess, (void*)remoteShellcodeAddr, shellcodeSize, PAGE_EXECUTE_READ, &oldProtect);

            CONTEXT newCtx = ctx;
            newCtx.Rip = remoteShellcodeAddr;
            if (!SetThreadContext(hThread, &newCtx)) {
                ResumeThread(hThread);
                CloseHandle(hThread);
                continue;
            }

            ResumeThread(hThread);

            bool completed = false;
            for (int i = 0; i < 40; i++) {
                Sleep(10);
                ULONG64 remoteResult[2] = { 0, 0 };
                if (ReadProcessMemory(hProcess, (void*)remoteDataAddr, remoteResult, sizeof(remoteResult), nullptr)) {
                    if (remoteResult[1] == 1) { // status == 1
                        hInjectedModule = (DWORD_PTR)remoteResult[0];
                        completed = true;
                        break;
                    }
                }
            }

            if (completed) {
                injected = true;
                CloseHandle(hThread);
                break;
            } else {
                if (SuspendThread(hThread) != (DWORD)-1) {
                    CONTEXT checkCtx;
                    checkCtx.ContextFlags = CONTEXT_FULL;
                    if (GetThreadContext(hThread, &checkCtx) && checkCtx.Rip == remoteShellcodeAddr) {
                        SetThreadContext(hThread, &ctx);
                    }
                    ResumeThread(hThread);
                }
                CloseHandle(hThread);
            }
        }

        if (injected && hInjectedModule != 0) {
            if (m_options.erasePe) {
                Utils::ErasePEHeaders(hProcess, (HMODULE)hInjectedModule);
            }
            if (m_options.unlinkPeb) {
                Utils::UnlinkModuleFromPEB(hProcess, (HMODULE)hInjectedModule);
            }
        }

        VirtualFreeEx(hProcess, pMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        if (injected) {
            return InjectionResult::Success("Successfully injected via Thread Hijacking.");
        } else {
            return InjectionResult::Failure("All thread hijack attempts timed out or failed to execute in target process.");
        }
    }

}
