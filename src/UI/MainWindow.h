#pragma once
#include <windows.h>
#include <vector>
#include <string>

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

        HINSTANCE m_hInstance;
        HWND m_hWnd;
        bool m_running;
        
        bool m_showSettings;
        int m_targetMode;
        char m_newExePath[MAX_PATH];
        
        std::vector<std::string> m_dllList;
        int m_selectedDllIndex;
        int m_selectedProcessIndex;

        static std::vector<std::string> s_DroppedFilesQueue;
    };

}
