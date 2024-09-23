#include "EasyService.h"
#include <iostream>
#include <windows.h>
#include <wtsapi32.h>
#include <userenv.h>
#include <string>
#pragma comment(lib, "Wtsapi32.lib")
#pragma comment(lib, "Userenv.lib")

SERVICE_STATUS        EasyService::g_ServiceStatus = {};
SERVICE_STATUS_HANDLE EasyService::g_StatusHandle = nullptr;
HANDLE                EasyService::g_ServiceStopEvent = nullptr;
EasyService::ServiceMainFunc EasyService::g_ServiceMainFunc = nullptr;
const wchar_t* m_ServiceName;

EasyService::EasyService(const wchar_t* serviceName, ServiceMainFunc serviceMainFunc) {
    m_ServiceName = serviceName;
    g_ServiceMainFunc = serviceMainFunc;
}

bool EasyService::Run() {
    SERVICE_TABLE_ENTRYW serviceTable[] = {
        { const_cast<LPWSTR>(m_ServiceName), EasyService::ServiceMain },
        { nullptr, nullptr }
    };

    return StartServiceCtrlDispatcherW(serviceTable) != 0;
}

bool EasyService::IsRunningAsService() {
    BOOL isService = FALSE;
    HANDLE token = nullptr;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        DWORD size = 0;
        GetTokenInformation(token, TokenSessionId, nullptr, 0, &size);

        DWORD sessionId = 0;
        if (GetTokenInformation(token, TokenSessionId, &sessionId, sizeof(DWORD), &size)) {
            isService = (sessionId == 0);
        }

        CloseHandle(token);
    }

    return isService;
}

void WINAPI EasyService::ServiceMain(DWORD argc, LPWSTR* argv) {
    g_StatusHandle = RegisterServiceCtrlHandlerW(m_ServiceName, EasyService::ServiceCtrlHandler);
    if (!g_StatusHandle) {
        return;
    }

    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;

    if (!SetServiceStatus(g_StatusHandle, &g_ServiceStatus)) {
        return;
    }

    g_ServiceStopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!g_ServiceStopEvent) {
        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        g_ServiceStatus.dwWin32ExitCode = GetLastError();
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
        return;
    }

    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;

    if (!SetServiceStatus(g_StatusHandle, &g_ServiceStatus)) {
        return;
    }

    HANDLE hThread = CreateThread(nullptr, 0, EasyService::ServiceWorkerThread, nullptr, 0, nullptr);
    if (hThread) {
        WaitForSingleObject(g_ServiceStopEvent, INFINITE);
        CloseHandle(hThread);
    }

    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
}

void WINAPI EasyService::ServiceCtrlHandler(DWORD ctrlCode) {
    if (ctrlCode == SERVICE_CONTROL_STOP && g_ServiceStatus.dwCurrentState == SERVICE_RUNNING) {
        g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
        SetEvent(g_ServiceStopEvent);
    }
}

DWORD WINAPI EasyService::ServiceWorkerThread(LPVOID lpParam) {
    if (g_ServiceMainFunc) {
        g_ServiceMainFunc();
    }

    SetEvent(g_ServiceStopEvent);
    return 0;
}
bool EasyService::LaunchProcess(const std::string& applicationPath, const std::string& applicationArgs, bool showWindow) {
    HANDLE userToken = nullptr;

    DWORD sessionId = WTSGetActiveConsoleSessionId();
    if (sessionId == 0xFFFFFFFF) {
        std::cerr << "No active user session found." << std::endl;
        return false;
    }

    if (!WTSQueryUserToken(sessionId, &userToken)) {
        std::cerr << "Failed to query user token: " << GetLastError() << std::endl;
        return false;
    }

    HANDLE duplicatedToken = nullptr;
    if (!DuplicateTokenEx(userToken, MAXIMUM_ALLOWED, nullptr, SecurityIdentification, TokenPrimary, &duplicatedToken)) {
        std::cerr << "Failed to duplicate token: " << GetLastError() << std::endl;
        CloseHandle(userToken);
        return false;
    }

    std::wstring appPathW(applicationPath.begin(), applicationPath.end());
    std::wstring appArgsW(applicationArgs.begin(), applicationArgs.end());
    std::wstring cmdLine = L"\"" + appPathW + L"\" " + appArgsW;

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    si.lpDesktop = const_cast<LPWSTR>(L"winsta0\\default");
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = showWindow ? SW_SHOWNORMAL : SW_HIDE;

    LPVOID environmentBlock = nullptr;
    if (!CreateEnvironmentBlock(&environmentBlock, duplicatedToken, FALSE)) {
        std::cerr << "Failed to create environment block: " << GetLastError() << std::endl;
        CloseHandle(userToken);
        CloseHandle(duplicatedToken);
        return false;
    }

    if (!CreateProcessAsUserW(duplicatedToken, nullptr, const_cast<LPWSTR>(cmdLine.c_str()), nullptr, nullptr, FALSE,
        CREATE_UNICODE_ENVIRONMENT, environmentBlock, nullptr, &si, &pi)) {
        std::cerr << "Failed to create process as user: " << GetLastError() << std::endl;
        DestroyEnvironmentBlock(environmentBlock);
        CloseHandle(userToken);
        CloseHandle(duplicatedToken);
        return false;
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    DestroyEnvironmentBlock(environmentBlock);
    CloseHandle(userToken);
    CloseHandle(duplicatedToken);

    return true;
}
bool EasyService::RunCommand(const std::string& Command, bool showWindow) {
    HANDLE userToken = nullptr;

    DWORD sessionId = WTSGetActiveConsoleSessionId();
    if (sessionId == 0xFFFFFFFF) {
        std::cerr << "No active user session found." << std::endl;
        return false;
    }

    if (!WTSQueryUserToken(sessionId, &userToken)) {
        std::cerr << "Failed to query user token: " << GetLastError() << std::endl;
        return false;
    }

    HANDLE duplicatedToken = nullptr;
    if (!DuplicateTokenEx(userToken, MAXIMUM_ALLOWED, nullptr, SecurityIdentification, TokenPrimary, &duplicatedToken)) {
        std::cerr << "Failed to duplicate token: " << GetLastError() << std::endl;
        CloseHandle(userToken);
        return false;
    }

    std::wstring cmdLine(Command.begin(), Command.end());
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    si.lpDesktop = const_cast<LPWSTR>(L"winsta0\\default");
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = showWindow ? SW_SHOWNORMAL : SW_HIDE;

    LPVOID environmentBlock = nullptr;
    if (!CreateEnvironmentBlock(&environmentBlock, duplicatedToken, FALSE)) {
        std::cerr << "Failed to create environment block: " << GetLastError() << std::endl;
        CloseHandle(userToken);
        CloseHandle(duplicatedToken);
        return false;
    }

    if (!CreateProcessAsUserW(duplicatedToken, nullptr, const_cast<LPWSTR>(cmdLine.c_str()), nullptr, nullptr, FALSE,
        CREATE_UNICODE_ENVIRONMENT, environmentBlock, nullptr, &si, &pi)) {
        std::cerr << "Failed to create process as user: " << GetLastError() << std::endl;
        DestroyEnvironmentBlock(environmentBlock);
        CloseHandle(userToken);
        CloseHandle(duplicatedToken);
        return false;
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    DestroyEnvironmentBlock(environmentBlock);
    CloseHandle(userToken);
    CloseHandle(duplicatedToken);

    return true;
}

bool IsServiceRunning(const wchar_t* serviceName) {
    SC_HANDLE scManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (scManager == nullptr) {
        return false;
    }

    SC_HANDLE scService = OpenService(scManager, serviceName, SERVICE_QUERY_STATUS);
    if (scService == nullptr) {
        CloseServiceHandle(scManager);
        return false;
    }

    SERVICE_STATUS_PROCESS ssStatus;
    DWORD bytesNeeded;
    bool isRunning = false;

    if (QueryServiceStatusEx(scService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssStatus, sizeof(SERVICE_STATUS_PROCESS), &bytesNeeded)) {
        isRunning = (ssStatus.dwCurrentState == SERVICE_RUNNING);
    }

    CloseServiceHandle(scService);
    CloseServiceHandle(scManager);
    return isRunning;
}

bool ManageService(const wchar_t* serviceName, int Type) {
    SC_HANDLE scManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (scManager == nullptr) {
        return false;
    }

    SC_HANDLE scService = OpenService(scManager, serviceName, Type);
    if (scService == nullptr) {
        CloseServiceHandle(scManager);
        return false;
    }

    bool success = StartService(scService, 0, nullptr);
    CloseServiceHandle(scService);
    CloseServiceHandle(scManager);
    return success;
}