#pragma once
#include <windows.h>
#include <string>

namespace Injection {

    struct [[nodiscard]] InjectionResult {
        bool success;
        DWORD errorCode;
        std::string message;

        static InjectionResult Success(const std::string& msg = "Injection successful.") {
            return { true, 0, msg };
        }

        static InjectionResult Failure(const std::string& msg, DWORD code = 0) {
            return { false, code, msg };
        }
    };

    class IInjector {
    public:
        virtual ~IInjector() = default;
        
        virtual InjectionResult Inject(DWORD pid, const std::string& dllPath) = 0;
    };

}
