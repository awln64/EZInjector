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

        InjectionResult Inject(DWORD pid, const std::string& dllPath) override;

    private:
        Options m_options;
    };
}
