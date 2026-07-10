#pragma once
#include "IInjector.h"

namespace Injection {

    class KernelNativeInjector : public IInjector {
    public:
        InjectionResult Inject(DWORD targetPid, const std::string& dllPath) override;
    };

}
