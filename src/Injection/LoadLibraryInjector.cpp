#include "LoadLibraryInjector.h"
#include "../Utils/ProcessUtils.h"
#include "../Utils/MemoryUtils.h"

namespace Injection {

    LoadLibraryInjector::LoadLibraryInjector(const Options& options) : m_options(options) {}

    bool LoadLibraryInjector::Inject(DWORD pid, const std::string& dllPath) {
        if (m_options.threadHijack) {
            return Inject_ThreadHijack(pid, dllPath);
        } else {
            return Inject_LoadLibrary(pid, dllPath);
        }
    }

    bool LoadLibraryInjector::Inject_LoadLibrary(DWORD pid, const std::string& dllPath) {
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProcess)
            return false;
        
        size_t pathLen = dllPath.length() + 1;
        void* pAllocatedMem = VirtualAllocEx(hProcess, nullptr, pathLen, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

        if (!pAllocatedMem) {
            CloseHandle(hProcess);
            return false;
        }
        
        WriteProcessMemory(hProcess, pAllocatedMem, dllPath.c_str(), pathLen, nullptr);
        
        FARPROC pLoadLibrary = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
        HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)pLoadLibrary, pAllocatedMem, 0, nullptr);
        
        if (!hThread) {
            VirtualFreeEx(hProcess, pAllocatedMem, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }
        
        WaitForSingleObject(hThread, INFINITE);
        
        DWORD_PTR hInjectedModule = 0;
        GetExitCodeThread(hThread, (LPDWORD)&hInjectedModule);
        
        if (m_options.erasePe && hInjectedModule != 0) {
            Utils::ErasePEHeaders(hProcess, (HMODULE)hInjectedModule);
        }
        
        if (m_options.unlinkPeb && hInjectedModule != 0) {
            Utils::UnlinkModuleFromPEB(hProcess, (HMODULE)hInjectedModule);
        }
        
        VirtualFreeEx(hProcess, pAllocatedMem, 0, MEM_RELEASE);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        
        return true;
    }

    bool LoadLibraryInjector::Inject_ThreadHijack(DWORD pid, const std::string& dllPath) {
        DWORD tid = Utils::GetTargetThreadId(pid);
        if (!tid)
            return false;

        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProcess)
            return false;

        HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, tid);
        if (!hThread) {
            CloseHandle(hProcess);
            return false;
        }

        SuspendThread(hThread);

        CONTEXT ctx;
        ctx.ContextFlags = CONTEXT_FULL;
        if (!GetThreadContext(hThread, &ctx)) {
            ResumeThread(hThread);
            CloseHandle(hThread);
            CloseHandle(hProcess);
            return false;
        }

        size_t pathLen = dllPath.length() + 1;
        size_t shellcodeSize = 100;

        void* pMem = VirtualAllocEx(hProcess, nullptr, pathLen + shellcodeSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

        if (!pMem) {
            ResumeThread(hThread);
            CloseHandle(hThread);
            CloseHandle(hProcess);
            return false;
        }

        uintptr_t remotePathAddr = (uintptr_t)pMem;
        uintptr_t remoteShellcodeAddr = remotePathAddr + pathLen;

        WriteProcessMemory(hProcess, (void*)remotePathAddr, dllPath.c_str(), pathLen, nullptr);

        FARPROC pLoadLibrary = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

        BYTE shellcode[] = {
            0x50,                   // push rax
            0x51,                   // push rcx
            0x52,                   // push rdx
            0x41, 0x50,             // push r8
            0x41, 0x51,             // push r9
            0x41, 0x52,             // push r10
            0x41, 0x53,             // push r11
            0x9C,                   // pushfq         ; save CPU flags
            0x48, 0x89, 0xE5,       // mov rbp, rsp   ; backup current stack pointer
            0x48, 0x83, 0xE4, 0xF0, // and rsp, 0xFFFFFFFFFFFFFFF0
                                    // align stack to 16 bytes (Win64 ABI)
            0x48, 0x83, 0xEC, 0x20, // sub rsp, 0x20  ; allocate shadow space
            0x48, 0xB9,             // mov rcx, <arg>
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, // placeholder: patched with argument pointer/value
            0x48, 0xB8,             // mov rax, <function>
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, // placeholder: patched with target function address
            0xFF, 0xD0,             // call rax
            0x48, 0x89, 0xEC,       // mov rsp, rbp     ; restore original stack pointer
            0x9D,                   // popfq
            0x41, 0x5B,             // pop r11
            0x41, 0x5A,             // pop r10
            0x41, 0x59,             // pop r9
            0x41, 0x58,             // pop r8
            0x5A,                   // pop rdx
            0x59,                   // pop rcx
            0x58,                   // pop rax
            0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, // jmp qword ptr [rip+0]
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00 // placeholder: patched with return address
        };

        memcpy(&shellcode[25], &remotePathAddr, sizeof(remotePathAddr));
        memcpy(&shellcode[35], &pLoadLibrary, sizeof(pLoadLibrary));
        memcpy(&shellcode[66], &ctx.Rip, sizeof(ctx.Rip));

        WriteProcessMemory(hProcess, (void*)remoteShellcodeAddr, shellcode, sizeof(shellcode), nullptr);

        ctx.Rip = remoteShellcodeAddr;
        SetThreadContext(hThread, &ctx);

        ResumeThread(hThread);

        Sleep(200);

        CloseHandle(hThread);
        CloseHandle(hProcess);
        return true;
    }

}
