#include <iomanip>
#include <windows.h>
#include <psapi.h>
#include <tchar.h> 

#define WIN32_LEAN_AND_MEAN

std::string TCHARToString(const TCHAR* tcharStr) {
    std::wstring wstr(tcharStr);
    std::string str(wstr.begin(), wstr.end());
    return str;
}

bool IsProgramRunning(const std::string& programName) {
    DWORD process_ids[1024], bytes_returned;

    if (!EnumProcesses(process_ids, sizeof(process_ids), &bytes_returned)) {
        return false;
    }

    unsigned int process_count = bytes_returned / sizeof(DWORD);
    for (unsigned int i = 0; i < process_count; i++) {
        if (process_ids[i] != 0) {
            HANDLE process_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, process_ids[i]);

            if (process_handle) {
                TCHAR process_name[MAX_PATH] = TEXT("<unknown>");
                HMODULE module;
                DWORD bytes_needed;

                if (EnumProcessModules(process_handle, &module, sizeof(module), &bytes_needed)) {
                    GetModuleBaseName(process_handle, module, process_name, sizeof(process_name) / sizeof(TCHAR));
                }

                std::string proc_name = TCHARToString(process_name);
                if (proc_name == programName) {
                    CloseHandle(process_handle);
                    return true;
                }

                CloseHandle(process_handle);
            }
        }
    }

    return false;
}
DWORD WaitForExit(const std::string& programName, DWORD timeout_ms = INFINITE) {
    unsigned int elapsed_time = 0;
    const unsigned int sleep_duration = 100; 

    if (!IsProgramRunning(programName))
        return ERROR_SUCCESS;

    while (IsProgramRunning(programName)) {
        if (timeout_ms != INFINITE && elapsed_time >= timeout_ms)
            return WAIT_TIMEOUT;
        Sleep(sleep_duration);
        elapsed_time += sleep_duration;
    }

    return ERROR_SUCCESS;
}

void EndProcess(const std::string& programName) {
    DWORD process_ids[1024], bytes_returned;

    if (!EnumProcesses(process_ids, sizeof(process_ids), &bytes_returned)) {
        return;
    }

    unsigned int process_count = bytes_returned / sizeof(DWORD);
    for (unsigned int i = 0; i < process_count; i++) {
        if (process_ids[i] != 0) {
            HANDLE process_handle = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, process_ids[i]);

            if (process_handle) {
                TCHAR process_name[MAX_PATH] = TEXT("<unknown>");
                HMODULE module;
                DWORD bytes_needed;

                if (EnumProcessModules(process_handle, &module, sizeof(module), &bytes_needed)) {
                    GetModuleBaseName(process_handle, module, process_name, sizeof(process_name) / sizeof(TCHAR));
                }

                std::string proc_name = TCHARToString(process_name);
                if (proc_name == programName) {
                    TerminateProcess(process_handle, 0);
                }

                CloseHandle(process_handle);
            }
        }
    }
}
time_t GetFileModificationTime(const std::string& filename) {
    struct stat result;
    if (stat(filename.c_str(), &result) == 0) {
        return result.st_mtime;
    }
    return 0;
}
