#include "MainWindow.h"
#include "DirectXSetup.h"
#include "../Utils/ProcessUtils.h"
#include "../Injection/InjectorManager.h"
#include "../../ImGui/imgui.h"
#include "../../ImGui/imgui_impl_dx11.h"
#include "../../ImGui/imgui_impl_win32.h"
#include <dwmapi.h>
#include <tchar.h>
#include <thread>

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
        // Ensure injection thread finishes before destroying members it references
        m_stopRequested.store(true);
        if (m_injectionThread.joinable()) {
            m_injectionThread.join();
        }

        ImGui_ImplDX11_Shutdown();
        ImGui_ImplWin32_Shutdown();
        ImGui::DestroyContext();
        CleanupDeviceD3D();
        if (m_hIcon) {
            DestroyIcon(m_hIcon);
            m_hIcon = nullptr;
        }
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
                    std::string path(filePath);
                    size_t dotPos = path.rfind('.');
                    if (dotPos != std::string::npos) {
                        std::string ext = path.substr(dotPos);
                        // Case-insensitive extension check
                        if (_stricmp(ext.c_str(), ".dll") == 0) {
                            s_DroppedFilesQueue.push_back(path);
                        }
                    }
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
        if (!RegisterClassEx(&wc)) {
            return false;
        }

        m_hWnd = CreateWindow(wc.lpszClassName, _T("EZ Injector by awalone"), WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
            100, 100, 450, 550, nullptr, nullptr, wc.hInstance, nullptr);

        COLORREF titleColor = 0x001C1717;
        DwmSetWindowAttribute(m_hWnd, 35, &titleColor, sizeof(titleColor));

        BYTE andMask[4] = { 0xFF, 0xFF, 0xFF, 0xFF };
        BYTE xorMask[4] = { 0x00, 0x00, 0x00, 0x00 };
        m_hIcon = CreateIcon(nullptr, 1, 1, 1, 32, andMask, xorMask);
        SendMessageW(m_hWnd, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(m_hIcon));

        DragAcceptFiles(m_hWnd, TRUE);

        // Allow drag & drop when running as administrator (UIPI blocks WM_DROPFILES by default)
        ChangeWindowMessageFilterEx(m_hWnd, WM_DROPFILES, MSGFLT_ALLOW, nullptr);
        ChangeWindowMessageFilterEx(m_hWnd, WM_COPYDATA, MSGFLT_ALLOW, nullptr);
        ChangeWindowMessageFilterEx(m_hWnd, 0x0049 /*WM_COPYGLOBALDATA*/, MSGFLT_ALLOW, nullptr);

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

            if (m_isInjecting) {
                std::lock_guard<std::mutex> lock(m_injectionMutex);
                ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.2f, 1.0f), "[PROCESSING] %s", m_injectionStatusText.c_str());
            } else {
                ImGui::Spacing();
            }

            ImGui::SetCursorPosY(viewport->Size.y - 50.0f);

            bool disableInject = m_isInjecting || m_dllList.empty();
            if (disableInject) {
                ImGui::BeginDisabled();
            }

            if (ImGui::Button(m_isInjecting ? "INJECTING..." : "INJECT", ImVec2(viewport->Size.x - 120, 40))) {
                StartAsyncInjection();
            }

            if (disableInject) {
                ImGui::EndDisabled();
            }

            ImGui::SameLine();
            if (ImGui::Button("Settings", ImVec2(-FLT_MIN, 40))) {
                m_showSettings = true;
            }
        }
        else {
            RenderSettings();
        }

        if (m_showResultModal.load()) {
            ImGui::OpenPopup("Injection Result");
        }

        if (ImGui::BeginPopupModal("Injection Result", NULL, ImGuiWindowFlags_AlwaysAutoResize)) {
            std::unique_lock<std::mutex> lock(m_injectionMutex);
            bool success = m_lastInjectionSuccess;
            std::string title = m_resultModalTitle;
            std::string msg = m_resultModalMessage;
            lock.unlock();

            if (success) {
                ImGui::TextColored(ImVec4(0.2f, 1.0f, 0.2f, 1.0f), "%s", title.c_str());
            } else {
                ImGui::TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), "%s", title.c_str());
            }
            ImGui::Separator();
            ImGui::Spacing();
            ImGui::TextUnformatted(msg.c_str());
            ImGui::Spacing();
            ImGui::Separator();
            if (ImGui::Button("OK", ImVec2(120, 0))) {
                std::lock_guard<std::mutex> lockClose(m_injectionMutex);
                m_showResultModal.store(false);
                ImGui::CloseCurrentPopup();
                if (success && g_InjectorConfig.closeAfter) {
                    PostMessage(m_hWnd, WM_CLOSE, 0, 0);
                }
            }
            ImGui::EndPopup();
        }

        ImGui::End();
    }

    void MainWindow::StartAsyncInjection() {
        if (m_isInjecting || m_dllList.empty()) return;

        DWORD targetPid = 0;
        HANDLE hNewProcessThread = nullptr;

        if (m_targetMode == 0) { // existing
            if (m_selectedProcessIndex >= 0 && m_selectedProcessIndex < (int)g_ProcessList.size()) {
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

        if (targetPid == 0) {
            std::lock_guard<std::mutex> lock(m_injectionMutex);
            m_lastInjectionSuccess = false;
            m_resultModalTitle = "Injection Error";
            m_resultModalMessage = "Failed to identify or spawn target process.";
            m_showResultModal.store(true);
            return;
        }

        m_isInjecting = true;
        {
            std::lock_guard<std::mutex> lock(m_injectionMutex);
            m_injectionStatusText = "Preparing injection into PID " + std::to_string(targetPid) + "...";
        }

        std::vector<std::string> dllsToInject = m_dllList;
        Injection::InjectorConfig config = g_InjectorConfig;

        // If a previous injection thread is still running, wait for it
        if (m_injectionThread.joinable()) {
            m_injectionThread.join();
        }

        m_stopRequested.store(false);
        m_injectionThread = std::thread([this, targetPid, hNewProcessThread, dllsToInject, config]() {
            LOG("Starting async injection into PID %lu", targetPid);
            auto injector = Injection::InjectorManager::CreateInjector(config);

            bool allSuccess = true;
            std::string fullSummary;

            if (!injector) {
                allSuccess = false;
                fullSummary = "[ERROR] Failed to create injector instance for selected injection method.";
            } else {
                for (size_t i = 0; i < dllsToInject.size(); ++i) {
                    if (m_stopRequested.load()) {
                        fullSummary += "[CANCELLED] Injection was cancelled.\n";
                        allSuccess = false;
                        break;
                    }
                    {
                        std::lock_guard<std::mutex> lock(m_injectionMutex);
                        m_injectionStatusText = "Injecting (" + std::to_string(i + 1) + "/" + std::to_string(dllsToInject.size()) + "): " + dllsToInject[i];
                    }
                    LOG("Injecting: %s", dllsToInject[i].c_str());

                    Injection::InjectionResult res = injector->Inject(targetPid, dllsToInject[i]);
                    if (res.success) {
                        LOG("  -> SUCCESS: %s", res.message.c_str());
                        fullSummary += "[SUCCESS] " + dllsToInject[i] + "\n  -> " + res.message + "\n\n";
                    } else {
                        LOG("  -> FAILED: %s (Error Code: %lu)", res.message.c_str(), res.errorCode);
                        fullSummary += "[FAILED] " + dllsToInject[i] + "\n  -> " + res.message;
                        if (res.errorCode != 0) {
                            fullSummary += " (Win32 Error: " + std::to_string(res.errorCode) + ")";
                        }
                        fullSummary += "\n\n";
                        allSuccess = false;
                        break;
                    }
                }
            }

            if (hNewProcessThread) {
                ResumeThread(hNewProcessThread);
                CloseHandle(hNewProcessThread);
            }

            LOG("Async injection complete. Overall: %s", allSuccess ? "SUCCESS" : "FAILED");

            {
                std::lock_guard<std::mutex> lock(m_injectionMutex);
                m_lastInjectionSuccess = allSuccess;
                m_resultModalTitle = allSuccess ? "Injection Successful" : "Injection Failed";
                m_resultModalMessage = fullSummary;
                m_showResultModal.store(true);
                m_isInjecting = false;
            }
        });
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
