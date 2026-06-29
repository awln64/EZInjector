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

        bool Inject(DWORD pid, const std::string& dllPath) override;

    private:
        bool Inject_LoadLibrary(DWORD pid, const std::string& dllPath);
        bool Inject_ThreadHijack(DWORD pid, const std::string& dllPath);

        Options m_options;
    };

}
