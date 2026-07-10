#pragma once
#include <windows.h>
#include <vector>
#include <string>

#include <atomic>
#include <mutex>

namespace UI {

    class MainWindow {
    public:
        MainWindow(HINSTANCE hInstance);
        ~MainWindow();

        bool Initialize();
        void Run();

        static LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

    private:
        void Render();
        void HandleDroppedFiles();
        void RenderSettings();
        void StartAsyncInjection();

        HINSTANCE m_hInstance;
        HWND m_hWnd;
        HICON m_hIcon = nullptr;
        bool m_running;
        
        bool m_showSettings;
        int m_targetMode;
        char m_newExePath[MAX_PATH];
        
        std::vector<std::string> m_dllList;
        int m_selectedDllIndex;
        int m_selectedProcessIndex;

        std::atomic<bool> m_isInjecting{false};
        std::string m_injectionStatusText;
        std::mutex m_injectionMutex;

        std::atomic<bool> m_showResultModal{false};
        bool m_lastInjectionSuccess{false};
        std::string m_resultModalTitle;
        std::string m_resultModalMessage;

        std::thread m_injectionThread;
        std::atomic<bool> m_stopRequested{false};

        static std::vector<std::string> s_DroppedFilesQueue;
    };

}
