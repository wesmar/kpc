#pragma once

#include <Windows.h>
#include <DbgHelp.h>
#include <Shellapi.h>
#include <Shlobj.h>
#include <accctrl.h>
#include <aclapi.h>
#include <iostream>
#include <string>
#include <optional>
#include <sstream>
#include <array>

// Build timestamp constants
#ifdef BUILD_DATE
    #define __DATE__ BUILD_DATE
#endif

#ifdef BUILD_TIME  
    #define __TIME__ BUILD_TIME
#endif

constexpr bool Kpc_DEBUG_ENABLED = false;

// Undefine Windows ERROR macro to avoid conflicts
#ifdef ERROR
#undef ERROR
#endif

template<typename... Args>
void PrintMessage(const wchar_t* prefix, const wchar_t* format, Args&&... args)
{
    std::wstringstream ss;
    ss << prefix;
    
    // Simple parameter expansion without std::format dependency
    if constexpr (sizeof...(args) == 0)
    {
        ss << format;
    }
    else
    {
        wchar_t buffer[1024];
        swprintf_s(buffer, format, std::forward<Args>(args)...);
        ss << buffer;
    }
    
    ss << L"\r\n";
    std::wcout << ss.str();
}

#if Kpc_DEBUG_ENABLED
    #define DEBUG(format, ...) PrintMessage(L"DEBUG: ", format, __VA_ARGS__)
#else
    #define DEBUG(format, ...) do {} while(0)
#endif

#define ERROR(format, ...) PrintMessage(L"[-] ", format, __VA_ARGS__)
#define INFO(format, ...) PrintMessage(L"[*] ", format, __VA_ARGS__)
#define SUCCESS(format, ...) PrintMessage(L"[+] ", format, __VA_ARGS__)

#define LASTERROR(f) \
    do { \
        wchar_t buf[256]; \
        swprintf_s(buf, L"[-] The function '%s' failed with error code 0x%08x.\r\n", L##f, GetLastError()); \
        std::wcout << buf; \
    } while(0)

enum class PS_PROTECTED_TYPE : UCHAR
{
    None = 0,
    ProtectedLight = 1,
    Protected = 2
};

enum class PS_PROTECTED_SIGNER : UCHAR
{
    None = 0,
    Authenticode = 1,
    CodeGen = 2,
    Antimalware = 3,
    Lsa = 4,
    Windows = 5,
    WinTcb = 6,
    WinSystem = 7,
    App = 8,
    Max = 9
};

// ======================= Enhanced String Obfuscation System =======================

template<size_t N>
struct XorString {
    constexpr XorString(const char (&str)[N]) {
        for (size_t i = 0; i < N; i++) {
            data[i] = str[i] ^ 0x7A;
        }
    }
    
    std::string decrypt() const {
        std::string result;
        result.reserve(N);
        for (size_t i = 0; i < N; i++) {
            if (data[i] == (0 ^ 0x7A)) break; // null terminator
            result += char(data[i] ^ 0x7A);
        }
        return result;
    }
    
    char data[N];
};

template<size_t N>
struct XorWString {
    constexpr XorWString(const wchar_t (&str)[N]) {
        for (size_t i = 0; i < N; i++) {
            data[i] = str[i] ^ 0x7A7A;
        }
    }
    
    std::wstring decrypt() const {
        std::wstring result;
        result.reserve(N);
        for (size_t i = 0; i < N; i++) {
            if (data[i] == (0 ^ 0x7A7A)) break; // null terminator
            result += wchar_t(data[i] ^ 0x7A7A);
        }
        return result;
    }
    
    wchar_t data[N];
};

// Enhanced obfuscation macros for different string categories
#define OBFSTR(str) []() -> std::string { \
    constexpr static XorString xorStr(str); \
    return xorStr.decrypt(); \
}()

#define OBFWSTR(str) []() -> std::wstring { \
    constexpr static XorWString xorStr(str); \
    return xorStr.decrypt(); \
}()

// API function name obfuscation
#define OBFAPI(api) []() -> std::string { \
    constexpr static XorString xorStr(api); \
    return xorStr.decrypt(); \
}()

// Process name obfuscation
#define OBFPROC(proc) []() -> std::wstring { \
    constexpr static XorWString xorStr(proc); \
    return xorStr.decrypt(); \
}()

// Privilege name obfuscation (returns LPCWSTR for Windows API compatibility)
#define OBFPRIV(priv) []() -> LPCWSTR { \
    static std::wstring cached = []() -> std::wstring { \
        constexpr static XorWString xorStr(priv); \
        return xorStr.decrypt(); \
    }(); \
    return cached.c_str(); \
}()

// Registry key obfuscation
#define OBFREG(key) []() -> std::wstring { \
    constexpr static XorWString xorStr(key); \
    return xorStr.decrypt(); \
}()

// Service name obfuscation
#define OBFSVC(svc) []() -> std::wstring { \
    constexpr static XorWString xorStr(svc); \
    return xorStr.decrypt(); \
}()

// File path obfuscation
#define OBFPATH(path) []() -> std::wstring { \
    constexpr static XorWString xorStr(path); \
    return xorStr.decrypt(); \
}()

// ======================= Dynamic API Loading Globals =======================
extern HMODULE g_advapi32;
extern HMODULE g_kernel32;
extern decltype(&CreateServiceW) g_pCreateServiceW;
extern decltype(&OpenServiceW) g_pOpenServiceW;
extern decltype(&StartServiceW) g_pStartServiceW;
extern decltype(&DeleteService) g_pDeleteService;
extern decltype(&CreateFileW) g_pCreateFileW;
extern decltype(&ControlService) g_pControlService;

bool InitDynamicAPIs() noexcept;
std::wstring GetServiceName() noexcept;
std::wstring GetDriverFileName() noexcept;
void GenerateFakeActivity() noexcept;

extern volatile bool g_interrupted;
