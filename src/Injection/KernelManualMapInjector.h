#pragma once
#include "IInjector.h"

namespace Injection {

    class KernelManualMapInjector : public IInjector {
    public:
        struct Options {
            bool linkPeb = false;
            bool erasePe = true;
            bool resolveImports = true;
            bool ignoreTls = false;
            bool concealMem = true;
            bool noExceptions = false;
        };

        KernelManualMapInjector(const Options& options);
        InjectionResult Inject(DWORD targetPid, const std::string& dllPath) override;

    private:
        Options m_options;
    };

}
