#include <windows.h>
#include <psapi.h>
#include <json/json.h>
#include <fstream>
#include <iostream>
#include <unordered_map>
#include <unordered_set>
#include <thread>
#include <sys/stat.h>
#include "BLib.h"
#include "EasyService.h"

DWORD GetPriorityClassFromValue(int value) {
    switch (value) {
    case 1: return IDLE_PRIORITY_CLASS;
    case 2: return BELOW_NORMAL_PRIORITY_CLASS;
    case 3: return NORMAL_PRIORITY_CLASS;
    case 4: return ABOVE_NORMAL_PRIORITY_CLASS;
    case 5: return HIGH_PRIORITY_CLASS;
    case 6: std::cerr << "Warning: Realtime priority may cause system instability.\n";
        return REALTIME_PRIORITY_CLASS;
    default: return NORMAL_PRIORITY_CLASS;
    }
}

bool SetProcessPriority(DWORD pid, int priorityValue) {
    HANDLE process_handle = OpenProcess(PROCESS_SET_INFORMATION, FALSE, pid);
    if (!process_handle) return false;

    bool result = SetPriorityClass(process_handle, GetPriorityClassFromValue(priorityValue));
    CloseHandle(process_handle);
    return result;
}

bool HandleProcessPriority(const std::string& processName, int priorityValue, std::unordered_set<DWORD>& handledPIDs) {
    DWORD process_ids[1024], bytes_returned;
    if (!EnumProcesses(process_ids, sizeof(process_ids), &bytes_returned)) return false;

    for (unsigned int i = 0; i < bytes_returned / sizeof(DWORD); i++) {
        if (process_ids[i] == 0 || handledPIDs.count(process_ids[i])) continue;

        HANDLE process_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, process_ids[i]);
        if (process_handle) {
            TCHAR process_name[MAX_PATH] = TEXT("<unknown>");
            HMODULE module; DWORD bytes_needed;
            if (EnumProcessModules(process_handle, &module, sizeof(module), &bytes_needed)) {
                GetModuleBaseName(process_handle, module, process_name, sizeof(process_name) / sizeof(TCHAR));
                if (TCHARToString(process_name) == processName) {
                    if (SetProcessPriority(process_ids[i], priorityValue)) {
                        handledPIDs.insert(process_ids[i]);
                    }
                }
            }
            CloseHandle(process_handle);
        }
    }
    return true;
}

std::unordered_map<std::string, int> ParseJsonConfig(const std::string& jsonFile) {
    std::unordered_map<std::string, int> processPriorityMap;
    std::ifstream file(jsonFile);
    if (!file.is_open()) return processPriorityMap;

    Json::Value root;
    file >> root;
    for (const auto& key : root.getMemberNames()) processPriorityMap[key] = root[key].asInt();

    return processPriorityMap;
}

void ApplyPriorityToAll(const std::unordered_map<std::string, int>& processPriorityMap, std::unordered_set<DWORD>& handledPIDs) {
    for (const auto& [name, priority] : processPriorityMap) {
        HandleProcessPriority(name, priority, handledPIDs);
        Sleep(10);
    }
}

void MainService() {
    std::string jsonFile = "priority.json";
    time_t lastModifiedTime = GetFileModificationTime(jsonFile);
    std::unordered_map<std::string, int> processPriorityMap = ParseJsonConfig(jsonFile);
    std::unordered_set<DWORD> handledPIDs;

    ApplyPriorityToAll(processPriorityMap, handledPIDs);
        
    while (true) {
        Sleep(2500);
        time_t currentModifiedTime = GetFileModificationTime(jsonFile);
        if (currentModifiedTime != lastModifiedTime) {
            std::cout << "JSON updated, reapplying priorities..." << std::endl;
            processPriorityMap = ParseJsonConfig(jsonFile);
            handledPIDs.clear();
            ApplyPriorityToAll(processPriorityMap, handledPIDs);
            lastModifiedTime = currentModifiedTime;
        }
        ApplyPriorityToAll(processPriorityMap, handledPIDs);
    }
}
int main() {
    EasyService Service(L"ProcessPriorityManager", MainService);
    if (EasyService::IsRunningAsService())
        Service.Run();
    else {
        std::cout << "Running In User Space Is Not Recommended, Please Start As A Service!" << std::endl;
        MainService();
    }
}