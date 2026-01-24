#pragma once
#include <windows.h>
#include <string>

DWORD djb2Hash(const char* str);
FARPROC getProcByHash(HMODULE hModule, DWORD hash);
