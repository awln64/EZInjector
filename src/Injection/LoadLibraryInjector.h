#pragma once
#include "IInjector.h"

namespace Injection {

    class LoadLibraryInjector : public IInjector {
    public:
        struct Options {
            bool unlinkPeb = true;
            bool erasePe = true;
            bool threadHijack = true;
        };

        LoadLibraryInjector(const Options& options);

        InjectionResult Inject(DWORD pid, const std::string& dllPath) override;

    private:
        InjectionResult Inject_LoadLibrary(DWORD pid, const std::string& dllPath);
        InjectionResult Inject_ThreadHijack(DWORD pid, const std::string& dllPath);

        Options m_options;
    };

}
