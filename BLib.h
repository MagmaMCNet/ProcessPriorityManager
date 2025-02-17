#pragma once
#include <string>
#include <tchar.h>

std::string TCHARToString(const TCHAR* tcharStr);
bool IsProgramRunning(const std::string& programName);
void EndProcess(const std::string& programName);
time_t GetFileModificationTime(const std::string& filename);
