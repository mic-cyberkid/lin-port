#pragma once

#include <cstdint>

typedef uint8_t BYTE;
typedef uint16_t WORD;
typedef uint32_t DWORD;
typedef uint64_t QWORD;
typedef void* HANDLE;
typedef HANDLE HWND;
typedef HANDLE HDC;
typedef HANDLE HBITMAP;
typedef HANDLE HGDIOBJ;
typedef long LONG;
typedef LONG HRESULT;

#define S_OK 0
#define E_FAIL -1
#define SUCCEEDED(hr) ((hr) >= 0)
#define FAILED(hr) ((hr) < 0)
