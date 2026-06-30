#pragma once
#include "IInjector.h"

namespace Injection {

    class KernelManualMapInjector : public IInjector {
    public:
        KernelManualMapInjector(bool linkPeb, bool erasePe, bool resolveImports, bool ignoreTls, bool concealMem, bool noExceptions);
        bool Inject(DWORD targetPid, const std::string& dllPath) override;

    private:
        bool m_linkPeb;
        bool m_erasePe;
        bool m_resolveImports;
        bool m_ignoreTls;
        bool m_concealMem;
        bool m_noExceptions;
    };

}
