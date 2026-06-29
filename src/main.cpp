#include <windows.h>
#include <cstdio>
#include "UI/MainWindow.h"

// ============================================================
// DEBUG / RELEASE logging macro
// In DEBUG builds: allocates console + prints diagnostic output
// In RELEASE builds: completely stripped — no console, no output
// ============================================================
#ifdef _DEBUG
#define LOG(fmt, ...) printf("[EZI] " fmt "\n", ##__VA_ARGS__)
#else
#define LOG(fmt, ...) ((void)0)
#endif

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "Comdlg32.lib")

#ifdef _DEBUG
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int);
int main() {
    return WinMain(GetModuleHandle(nullptr), nullptr, GetCommandLineA(), SW_SHOWDEFAULT);
}
#endif

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int) {

#ifdef _DEBUG
    AllocConsole();
    SetConsoleTitleA("EZ Injector — Debug Console");
    FILE* fp = nullptr;
    freopen_s(&fp, "CONOUT$", "w", stdout);
    freopen_s(&fp, "CONOUT$", "w", stderr);
    LOG("Debug console initialized");
    LOG("Build: DEBUG | Compiled: %s %s", __DATE__, __TIME__);
#endif

    UI::MainWindow mainWindow(hInstance);

    if (!mainWindow.Initialize()) {
        return 1;
    }

    mainWindow.Run();

#ifdef _DEBUG
    LOG("Shutting down...");
    FreeConsole();
#endif

    return 0;
}
