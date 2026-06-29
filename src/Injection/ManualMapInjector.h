#pragma once
#include "IInjector.h"

namespace Injection {

    class ManualMapInjector : public IInjector {
    public:
        struct Options {
            bool linkPeb = false;
            bool erasePe = true;
            bool resolveImports = true;
            bool ignoreTls = false;
            bool concealMem = true;
            bool noExceptions = false;
        };

        ManualMapInjector(const Options& options);

        bool Inject(DWORD pid, const std::string& dllPath) override;

    private:
        Options m_options;
    };

    struct ManualMapData {
        BYTE* ImageBase;
        ULONGLONG RelocationDelta;
        IMAGE_BASE_RELOCATION* pBaseReloc;
        IMAGE_IMPORT_DESCRIPTOR* pImportDesc;
        IMAGE_TLS_DIRECTORY* pTlsDir;
        RUNTIME_FUNCTION* pExceptionDir;
        DWORD ExceptionSize;
        PVOID EntryPoint;
        decltype(&LoadLibraryA) fnLoadLibraryA;
        decltype(&GetProcAddress) fnGetProcAddress;
        decltype(&RtlAddFunctionTable) fnRtlAddFunctionTable;
        BOOL ResolveImports;
        BOOL IgnoreTls;
        BOOL NoExceptions;
        BOOL Success;
    };

}
