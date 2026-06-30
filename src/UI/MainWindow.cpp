#include "MainWindow.h"
#include "DirectXSetup.h"
#include "../Utils/ProcessUtils.h"
#include "../Injection/InjectorManager.h"
#include "../../ImGui/imgui.h"
#include "../../ImGui/imgui_impl_dx11.h"
#include "../../ImGui/imgui_impl_win32.h"
#include <dwmapi.h>
#include <tchar.h>

#ifdef _DEBUG
#define LOG(fmt, ...) printf("[EZI] " fmt "\n", ##__VA_ARGS__)
#else
#define LOG(fmt, ...) ((void)0)
#endif

extern LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

namespace UI {

    std::vector<std::string> MainWindow::s_DroppedFilesQueue;
    static std::vector<Utils::ProcessInfo> g_ProcessList;
    static Injection::InjectorConfig g_InjectorConfig;

    static auto VectorGetter = [](void* data, int idx) -> const char* {
        auto* list = (std::vector<Utils::ProcessInfo>*)data;
        if (idx < 0 || idx >= list->size())
            return nullptr;
        return (*list)[idx].displayName.c_str();
    };

    MainWindow::MainWindow(HINSTANCE hInstance)
        : m_hInstance(hInstance), m_hWnd(nullptr), m_running(true),
          m_showSettings(false), m_targetMode(0), m_selectedDllIndex(-1), m_selectedProcessIndex(0) {
        m_newExePath[0] = '\0';
    }

    MainWindow::~MainWindow() {
        ImGui_ImplDX11_Shutdown();
        ImGui_ImplWin32_Shutdown();
        ImGui::DestroyContext();
        CleanupDeviceD3D();
        if (m_hWnd) {
            DestroyWindow(m_hWnd);
        }
        UnregisterClass(_T("MonolithImGui"), m_hInstance);
    }

    LRESULT WINAPI MainWindow::WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
        if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
            return true;

        switch (msg) {
        case WM_DROPFILES: {
            HDROP hDrop = (HDROP)wParam;
            UINT fileCount = DragQueryFileA(hDrop, 0xFFFFFFFF, nullptr, 0);
            for (UINT i = 0; i < fileCount; ++i) {
                char filePath[MAX_PATH];
                if (DragQueryFileA(hDrop, i, filePath, MAX_PATH)) {
                    s_DroppedFilesQueue.push_back(filePath);
                }
            }
            DragFinish(hDrop);
            return 0;
        }
        case WM_SIZE: {
            if (g_pd3dDevice != nullptr && wParam != SIZE_MINIMIZED) {
                CleanupRenderTarget();
                g_pSwapChain->ResizeBuffers(0, (UINT)LOWORD(lParam), (UINT)HIWORD(lParam), DXGI_FORMAT_UNKNOWN, 0);
                CreateRenderTarget();
            }
            return 0;
        }
        case WM_DESTROY: {
            PostQuitMessage(0);
            return 0;
        }
        }
        return DefWindowProc(hWnd, msg, wParam, lParam);
    }

    bool MainWindow::Initialize() {
        WNDCLASSEX wc = { sizeof(WNDCLASSEX),  CS_CLASSDC, WndProc, 0L, 0L,
                         m_hInstance, nullptr, nullptr, nullptr, nullptr,
                         _T("MonolithImGui"), nullptr };
        RegisterClassEx(&wc);

        m_hWnd = CreateWindow(wc.lpszClassName, _T("EZ Injector by awalone"), WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
            100, 100, 450, 550, nullptr, nullptr, wc.hInstance, nullptr);

        COLORREF titleColor = 0x001C1717;
        DwmSetWindowAttribute(m_hWnd, 35, &titleColor, sizeof(titleColor));

        BYTE andMask[4] = { 0xFF, 0xFF, 0xFF, 0xFF };
        BYTE xorMask[4] = { 0x00, 0x00, 0x00, 0x00 };
        HICON hInvisibleIcon = CreateIcon(nullptr, 1, 1, 1, 32, andMask, xorMask);
        SendMessageW(m_hWnd, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(hInvisibleIcon));

        DragAcceptFiles(m_hWnd, TRUE);

        if (!CreateDeviceD3D(m_hWnd)) {
            CleanupDeviceD3D();
            UnregisterClass(wc.lpszClassName, wc.hInstance);
            return false;
        }

        ShowWindow(m_hWnd, SW_SHOWDEFAULT);
        UpdateWindow(m_hWnd);

        IMGUI_CHECKVERSION();
        ImGui::CreateContext();
        ImGuiIO& io = ImGui::GetIO();
        io.IniFilename = nullptr;
        io.LogFilename = nullptr;

        ImGui::StyleColorsDark();
        ImGuiStyle& style = ImGui::GetStyle();
        style.WindowRounding = 0.0f;
        style.FrameRounding = 4.0f;
        style.WindowBorderSize = 0.0f;
        style.GrabRounding = 4.0f;

        ImGui_ImplWin32_Init(m_hWnd);
        ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

        g_ProcessList = Utils::GetProcessList();
        return true;
    }

    void MainWindow::HandleDroppedFiles() {
        if (!s_DroppedFilesQueue.empty()) {
            for (const auto& file : s_DroppedFilesQueue) {
                m_dllList.push_back(file);
            }
            s_DroppedFilesQueue.clear();
        }
    }

    void MainWindow::RenderSettings() {
        ImGui::TextColored(ImVec4(0.5f, 0.8f, 1.0f, 1.0f), "INJECTION SETTINGS");
        ImGui::Separator();
        ImGui::Spacing();

        ImGui::Text("Method:");
        int method = (int)g_InjectorConfig.method;
        ImGui::RadioButton("LoadLibrary (Standard)", &method, 0);
        ImGui::RadioButton("Manual Mapping", &method, 1);
        ImGui::RadioButton("Kernel Native Inject", &method, 2);
        ImGui::RadioButton("Kernel Manual Map", &method, 3);
        g_InjectorConfig.method = (Injection::InjectionMethod)method;

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        ImGui::TextColored(ImVec4(0.8f, 0.8f, 0.8f, 1.0f), "Options:");

        if (g_InjectorConfig.method == Injection::InjectionMethod::LoadLibrary) {
            ImGui::Checkbox("Unlink from PEB", &g_InjectorConfig.llUnlinkPeb);
            ImGui::Checkbox("Erase PE Headers", &g_InjectorConfig.llErasePe);
            ImGui::Checkbox("Use existing thread (Thread Hi-jacking)", &g_InjectorConfig.llThreadHijack);
        }
        else if (g_InjectorConfig.method == Injection::InjectionMethod::ManualMap || g_InjectorConfig.method == Injection::InjectionMethod::KernelManualMap) {
            if (g_InjectorConfig.method == Injection::InjectionMethod::KernelManualMap) {
                ImGui::TextColored(ImVec4(0.4f, 0.9f, 0.4f, 1.0f), "[Kernel Mode Mapping Active]");
            }
            ImGui::Checkbox("Link to PEB", &g_InjectorConfig.mmLinkPeb);
            ImGui::Checkbox("Erase PE Headers", &g_InjectorConfig.mmErasePe);
            ImGui::Checkbox("Resolve imports", &g_InjectorConfig.mmResolveImports);
            ImGui::Checkbox("Ignore TLS", &g_InjectorConfig.mmIgnoreTls);
            ImGui::Checkbox("Conceal memory", &g_InjectorConfig.mmConcealMem);
            ImGui::Checkbox("No exception support", &g_InjectorConfig.mmNoExceptions);
        }
        else if (g_InjectorConfig.method == Injection::InjectionMethod::KernelNative) {
            ImGui::TextColored(ImVec4(0.4f, 0.9f, 0.4f, 1.0f), "[Ring-0 APC / Shellcode Delivery Active]");
            ImGui::TextWrapped("Injects via kernel mode driver (\\Device\\EZInjectorKernel) bypassing standard usermode API hooks.");
        }

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        ImGui::Checkbox("Close Injector after success", &g_InjectorConfig.closeAfter);

        ImGuiViewport* viewport = ImGui::GetMainViewport();
        ImGui::SetCursorPosY(viewport->Size.y - 50.0f);
        if (ImGui::Button("Back", ImVec2(-FLT_MIN, 40))) {
            m_showSettings = false;
        }
    }

    void MainWindow::Render() {
        ImGuiViewport* viewport = ImGui::GetMainViewport();
        ImGui::SetNextWindowPos(viewport->Pos);
        ImGui::SetNextWindowSize(viewport->Size);

        ImGuiWindowFlags flags = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
            ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoSavedSettings;

        ImGui::Begin("Root", nullptr, flags);

        if (!m_showSettings) {
            ImGui::TextColored(ImVec4(0.5f, 0.8f, 1.0f, 1.0f), "TARGET PROCESS");
            ImGui::Separator();

            ImGui::RadioButton("Existing", &m_targetMode, 0);
            ImGui::SameLine();
            ImGui::RadioButton("New", &m_targetMode, 1);

            ImGui::Spacing();

            if (m_targetMode == 0) {
                ImGui::SetNextItemWidth(viewport->Size.x - 90);
                ImGui::Combo("##ProcessCombo", &m_selectedProcessIndex, VectorGetter, (void*)&g_ProcessList, (int)g_ProcessList.size());

                ImGui::SameLine();
                if (ImGui::Button("Refresh", ImVec2(-FLT_MIN, 0))) {
                    g_ProcessList = Utils::GetProcessList();
                    m_selectedProcessIndex = 0;
                }
            }
            else {
                ImGui::SetNextItemWidth(viewport->Size.x - 90);
                ImGui::InputText("##NewExePath", m_newExePath, MAX_PATH);
                ImGui::SameLine();
                if (ImGui::Button("Browse", ImVec2(-FLT_MIN, 0))) {
                    std::string file = Utils::OpenFileDialog("Executables (*.exe)\0*.exe\0All Files (*.*)\0*.*\0", m_hWnd);
                    if (!file.empty()) {
                        strncpy_s(m_newExePath, file.c_str(), _TRUNCATE);
                    }
                }
            }

            ImGui::Spacing();
            ImGui::Spacing();

            ImGui::TextColored(ImVec4(0.5f, 0.8f, 1.0f, 1.0f), "PAYLOADS");
            ImGui::Separator();

            if (ImGui::BeginListBox("##DllList", ImVec2(-FLT_MIN, 150))) {
                for (int i = 0; i < m_dllList.size(); i++) {
                    const bool is_selected = (m_selectedDllIndex == i);
                    size_t slashPos = m_dllList[i].find_last_of("/\\");
                    std::string displayName = (slashPos != std::string::npos) ? m_dllList[i].substr(slashPos + 1) : m_dllList[i];

                    if (ImGui::Selectable(displayName.c_str(), is_selected)) {
                        m_selectedDllIndex = i;
                    }
                    if (is_selected) {
                        ImGui::SetItemDefaultFocus();
                    }
                    if (ImGui::IsItemHovered()) {
                        ImGui::SetTooltip("%s", m_dllList[i].c_str());
                    }
                }
                ImGui::EndListBox();
            }

            if (ImGui::Button("Add", ImVec2(70, 0))) {
                std::string file = Utils::OpenFileDialog("DLL Files (*.dll)\0*.dll\0All Files (*.*)\0*.*\0", m_hWnd);
                if (!file.empty()) {
                    m_dllList.push_back(file);
                }
            }

            ImGui::SameLine();
            if (ImGui::Button("Remove", ImVec2(70, 0))) {
                if (m_selectedDllIndex >= 0 && m_selectedDllIndex < m_dllList.size()) {
                    m_dllList.erase(m_dllList.begin() + m_selectedDllIndex);
                    m_selectedDllIndex = -1;
                }
            }

            ImGui::SameLine();
            if (ImGui::Button("Clear", ImVec2(70, 0))) {
                m_dllList.clear();
                m_selectedDllIndex = -1;
            }

            ImGui::Spacing();
            ImGui::Spacing();
            ImGui::Separator();
            ImGui::Spacing();

            ImGui::SetCursorPosY(viewport->Size.y - 50.0f);

            if (ImGui::Button("INJECT", ImVec2(viewport->Size.x - 120, 40))) {
                if (!m_dllList.empty()) {
                    DWORD targetPid = 0;
                    HANDLE hNewProcessThread = nullptr;

                    if (m_targetMode == 0) { // existing
                        if (m_selectedProcessIndex >= 0 && m_selectedProcessIndex < g_ProcessList.size()) {
                            targetPid = g_ProcessList[m_selectedProcessIndex].pid;
                        }
                    }
                    else { // new
                        STARTUPINFOA si = { sizeof(si) };
                        PROCESS_INFORMATION pi = { 0 };

                        if (CreateProcessA(m_newExePath, nullptr, nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
                            targetPid = pi.dwProcessId;
                            hNewProcessThread = pi.hThread;
                            CloseHandle(pi.hProcess);
                        }
                    }

                    if (targetPid != 0) {
                        bool allSuccess = true;
                        LOG("Starting injection into PID %lu", targetPid);
                        
                        auto injector = Injection::InjectorManager::CreateInjector(g_InjectorConfig);

                        for (const auto& dll : m_dllList) {
                            LOG("Injecting: %s", dll.c_str());
                            if (!injector->Inject(targetPid, dll)) {
                                LOG("  -> FAILED");
                                allSuccess = false;
                                break;
                            }
                            LOG("  -> SUCCESS");
                        }

                        LOG("Injection complete. Overall: %s", allSuccess ? "SUCCESS" : "FAILED");

                        if (hNewProcessThread) {
                            ResumeThread(hNewProcessThread);
                            CloseHandle(hNewProcessThread);
                        }

                        if (allSuccess && g_InjectorConfig.closeAfter) {
                            PostMessage(m_hWnd, WM_CLOSE, 0, 0);
                        }
                    }
                }
            }
            ImGui::SameLine();
            if (ImGui::Button("Settings", ImVec2(-FLT_MIN, 40))) {
                m_showSettings = true;
            }
        }
        else {
            RenderSettings();
        }

        ImGui::End();
    }

    void MainWindow::Run() {
        while (m_running) {
            MSG msg;
            while (PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE)) {
                TranslateMessage(&msg);
                DispatchMessage(&msg);
                if (msg.message == WM_QUIT) {
                    m_running = false;
                }
            }

            if (!m_running) break;

            HandleDroppedFiles();

            ImGui_ImplDX11_NewFrame();
            ImGui_ImplWin32_NewFrame();
            ImGui::NewFrame();

            Render();

            ImGui::Render();
            const float clearColor[4] = { 0.08f, 0.08f, 0.10f, 1.0f };
            g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
            g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clearColor);
            ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
            g_pSwapChain->Present(1, 0);
        }
    }
}
