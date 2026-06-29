#pragma once
#include <windows.h>
#include <string>

namespace Injection {

    class IInjector {
    public:
        virtual ~IInjector() = default;
        
        // Return true if injection succeeds, false otherwise.
        virtual bool Inject(DWORD pid, const std::string& dllPath) = 0;
    };

}
