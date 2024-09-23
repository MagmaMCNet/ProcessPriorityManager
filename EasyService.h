#pragma once
#ifndef EASYSERVICE_H
#define EASYSERVICE_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <functional>
#include <string>

#pragma comment(lib, "ws2_32.lib")

class EasyService {
public:
    using ServiceMainFunc = std::function<void()>;

    EasyService(const wchar_t* serviceName, ServiceMainFunc serviceMainFunc);
    bool Run();
    static bool IsRunningAsService();
    bool LaunchProcess(const std::string& applicationPath, const std::string& applicationArgs, bool showWindow);
    bool RunCommand(const std::string& Command, bool showWindow);
private:
    static void WINAPI ServiceMain(DWORD argc, LPWSTR* argv);
    static void WINAPI ServiceCtrlHandler(DWORD ctrlCode);
    static DWORD WINAPI ServiceWorkerThread(LPVOID lpParam);

    static SERVICE_STATUS        g_ServiceStatus;
    static SERVICE_STATUS_HANDLE g_StatusHandle;
    static HANDLE                g_ServiceStopEvent;
    static ServiceMainFunc       g_ServiceMainFunc;
};
static bool IsServiceRunning(const wchar_t* serviceName);
static bool ManageService(const wchar_t* serviceName, int Type);
#endif // EASYSERVICE_H
