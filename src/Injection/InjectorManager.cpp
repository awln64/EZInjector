#include "InjectorManager.h"
#include "LoadLibraryInjector.h"
#include "ManualMapInjector.h"

namespace Injection {

    std::unique_ptr<IInjector> InjectorManager::CreateInjector(const InjectorConfig& config) {
        if (config.method == InjectionMethod::LoadLibrary) {
            LoadLibraryInjector::Options opts;
            opts.unlinkPeb = config.llUnlinkPeb;
            opts.erasePe = config.llErasePe;
            opts.threadHijack = config.llThreadHijack;
            return std::make_unique<LoadLibraryInjector>(opts);
        }
        else if (config.method == InjectionMethod::ManualMap) {
            ManualMapInjector::Options opts;
            opts.linkPeb = config.mmLinkPeb;
            opts.erasePe = config.mmErasePe;
            opts.resolveImports = config.mmResolveImports;
            opts.ignoreTls = config.mmIgnoreTls;
            opts.concealMem = config.mmConcealMem;
            opts.noExceptions = config.mmNoExceptions;
            return std::make_unique<ManualMapInjector>(opts);
        }
        
        return nullptr;
    }

}
