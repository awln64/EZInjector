#pragma once
#include "IInjector.h"
#include <memory>
#include <string>

namespace Injection {

    enum class InjectionMethod {
        LoadLibrary,
        ManualMap
    };

    struct InjectorConfig {
        InjectionMethod method = InjectionMethod::LoadLibrary;
        
        // LoadLibrary settings
        bool llUnlinkPeb = true;
        bool llErasePe = true;
        bool llThreadHijack = true;

        // ManualMap settings
        bool mmLinkPeb = false;
        bool mmErasePe = true;
        bool mmResolveImports = true;
        bool mmIgnoreTls = false;
        bool mmConcealMem = true;
        bool mmNoExceptions = false;

        bool closeAfter = false;
    };

    class InjectorManager {
    public:
        static std::unique_ptr<IInjector> CreateInjector(const InjectorConfig& config);
    };

}
