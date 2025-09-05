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

#include "TrustedInstallerIntegrator.h"
#include "common.h"
#include <tchar.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <objbase.h>
#include <iostream>
#include <algorithm>
#include <cctype>
#include <filesystem>

namespace fs = std::filesystem;

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shell32.lib")

// Complete system privilege set for maximum access elevation
const LPCWSTR TrustedInstallerIntegrator::ALL_PRIVILEGES[] = {
    OBFPRIV(L"SeAssignPrimaryTokenPrivilege"),
    OBFPRIV(L"SeBackupPrivilege"),
    OBFPRIV(L"SeRestorePrivilege"),
    OBFPRIV(L"SeDebugPrivilege"),
    OBFPRIV(L"SeImpersonatePrivilege"),
    OBFPRIV(L"SeTakeOwnershipPrivilege"),
    OBFPRIV(L"SeLoadDriverPrivilege"),
    OBFPRIV(L"SeSystemEnvironmentPrivilege"),
    OBFPRIV(L"SeManageVolumePrivilege"),
    OBFPRIV(L"SeSecurityPrivilege"),
    OBFPRIV(L"SeShutdownPrivilege"),
    OBFPRIV(L"SeSystemtimePrivilege"),
    OBFPRIV(L"SeTcbPrivilege"),
    OBFPRIV(L"SeIncreaseQuotaPrivilege"),
    OBFPRIV(L"SeAuditPrivilege"),
    OBFPRIV(L"SeChangeNotifyPrivilege"),
    OBFPRIV(L"SeUndockPrivilege"),
    OBFPRIV(L"SeCreateTokenPrivilege"),
    OBFPRIV(L"SeLockMemoryPrivilege"),
    OBFPRIV(L"SeCreatePagefilePrivilege"),
    OBFPRIV(L"SeCreatePermanentPrivilege"),
    OBFPRIV(L"SeSystemProfilePrivilege"),
    OBFPRIV(L"SeProfileSingleProcessPrivilege"),
    OBFPRIV(L"SeCreateGlobalPrivilege"),
    OBFPRIV(L"SeTimeZonePrivilege"),
    OBFPRIV(L"SeCreateSymbolicLinkPrivilege"),
    OBFPRIV(L"SeIncreaseBasePriorityPrivilege"),
    OBFPRIV(L"SeRemoteShutdownPrivilege"),  
    OBFPRIV(L"SeIncreaseWorkingSetPrivilege")
};

const int TrustedInstallerIntegrator::PRIVILEGE_COUNT = sizeof(TrustedInstallerIntegrator::ALL_PRIVILEGES) / sizeof(LPCWSTR);

// Cache for TrustedInstaller token
static HANDLE g_cachedTrustedInstallerToken = nullptr;
static DWORD g_lastTokenAccessTime = 0;
static const DWORD TOKEN_CACHE_TIMEOUT = 30000; // 30 seconds

TrustedInstallerIntegrator::TrustedInstallerIntegrator()
{
    CoInitialize(NULL);
}

TrustedInstallerIntegrator::~TrustedInstallerIntegrator()
{
    CoUninitialize();
    
    // Cleanup cached token
    if (g_cachedTrustedInstallerToken) {
        CloseHandle(g_cachedTrustedInstallerToken);
        g_cachedTrustedInstallerToken = nullptr;
    }
}

HANDLE TrustedInstallerIntegrator::GetCachedTrustedInstallerToken() {
    DWORD currentTime = GetTickCount();
    
    // Return cached token if still valid
    if (g_cachedTrustedInstallerToken && 
        (currentTime - g_lastTokenAccessTime) < TOKEN_CACHE_TIMEOUT) {
        return g_cachedTrustedInstallerToken;
    }
    
    // Cleanup old token
    if (g_cachedTrustedInstallerToken) {
        CloseHandle(g_cachedTrustedInstallerToken);
        g_cachedTrustedInstallerToken = nullptr;
    }
    
    // Get new token
    DWORD tiPid = StartTrustedInstallerService();
    if (!tiPid) return nullptr;
    
    HANDLE hTIProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, tiPid);
    if (!hTIProcess) return nullptr;
    
    HANDLE hTIToken;
    if (!OpenProcessToken(hTIProcess, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hTIToken)) {
        CloseHandle(hTIProcess);
        return nullptr;
    }
    
    // Duplicate token for caching
    HANDLE hDupToken;
    if (!DuplicateTokenEx(hTIToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, 
                         TokenImpersonation, &hDupToken)) {
        CloseHandle(hTIToken);
        CloseHandle(hTIProcess);
        return nullptr;
    }
    
    CloseHandle(hTIToken);
    CloseHandle(hTIProcess);
    
    // Enable privileges on the duplicated token
    for (int i = 0; i < PRIVILEGE_COUNT; i++) {
        TOKEN_PRIVILEGES tp;
        LUID luid;
        
        if (LookupPrivilegeValueW(NULL, ALL_PRIVILEGES[i], &luid)) {
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(hDupToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
        }
    }
    
    // Cache the token
    g_cachedTrustedInstallerToken = hDupToken;
    g_lastTokenAccessTime = currentTime;
    
    return g_cachedTrustedInstallerToken;
}

BOOL TrustedInstallerIntegrator::IsLnkFile(LPCWSTR filePath)
{
    if (!filePath || wcslen(filePath) < 4) 
        return FALSE;
    
    fs::path path(filePath);
    std::wstring ext = path.extension().wstring();
    
    auto lnkExtension = OBFPATH(L".lnk");
    return _wcsicmp(ext.c_str(), lnkExtension.c_str()) == 0;  // Case-insensitive comparison
}

std::wstring TrustedInstallerIntegrator::ResolveLnk(LPCWSTR lnkPath)
{
    std::wstring result;
    IShellLinkW* psl = nullptr;
    IPersistFile* ppf = nullptr;
    
    // Check if file exists
    if (GetFileAttributesW(lnkPath) == INVALID_FILE_ATTRIBUTES)
    {
        std::wcout << OBFERR(L"Shortcut file does not exist: ") << lnkPath << std::endl;
        return result;
    }

    // Create ShellLink instance
    HRESULT hres = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLinkW, (LPVOID*)&psl);
    if (FAILED(hres))
    {
        std::wcout << OBFERR(L"Failed to create ShellLink instance: 0x") << std::hex << hres << std::endl;
        return result;
    }

    // Get IPersistFile interface
    hres = psl->QueryInterface(IID_IPersistFile, (LPVOID*)&ppf);
    if (FAILED(hres))
    {
        std::wcout << OBFERR(L"Failed to get IPersistFile interface: 0x") << std::hex << hres << std::endl;
        psl->Release();
        return result;
    }

    // Load shortcut file
    hres = ppf->Load(lnkPath, STGM_READ);
    if (FAILED(hres))
    {
        std::wcout << OBFERR(L"Failed to load shortcut file: 0x") << std::hex << hres << std::endl;
        ppf->Release();
        psl->Release();
        return result;
    }

    // Get target path
    wchar_t targetPath[MAX_PATH * 2] = {0};
    WIN32_FIND_DATAW wfd = {0};
    
    hres = psl->GetPath(targetPath, MAX_PATH * 2, &wfd, SLGP_RAWPATH);
    if (FAILED(hres))
    {
        std::wcout << OBFERR(L"Failed to get shortcut target path: 0x") << std::hex << hres << std::endl;
    }
    else if (wcslen(targetPath) > 0)
    {
        result = targetPath;
        
        // Get arguments if any
        wchar_t args[MAX_PATH * 2] = {0};
        hres = psl->GetArguments(args, MAX_PATH * 2);
        if (SUCCEEDED(hres) && wcslen(args) > 0)
        {
            result += OBFPATH(L" ");
            result += args;
        }
    }

    // Cleanup
    ppf->Release();
    psl->Release();
    
    return result;
}

BOOL TrustedInstallerIntegrator::EnablePrivilege(LPCWSTR privilegeName)
{
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken))
        return FALSE;

    LUID luid;
    if (!LookupPrivilegeValueW(NULL, privilegeName, &luid))
    {
        CloseHandle(hToken);
        return FALSE;
    }

    TOKEN_PRIVILEGES tp = { 0 };
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL result = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
    CloseHandle(hToken);
    
    return result && (GetLastError() == ERROR_SUCCESS);
}

DWORD TrustedInstallerIntegrator::GetProcessIdByName(LPCWSTR processName)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return 0;

    DWORD pid = 0;
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnapshot, &pe))
    {
        do
        {
            if (wcscmp(pe.szExeFile, processName) == 0)
            {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return pid;
}

BOOL TrustedInstallerIntegrator::ImpersonateSystem()
{
    auto winlogonProcess = OBFPROC(L"winlogon.exe");
    DWORD systemPid = GetProcessIdByName(winlogonProcess.c_str());
    if (systemPid == 0)
        return FALSE;

    HANDLE hSystemProcess = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, systemPid);
    if (!hSystemProcess)
        return FALSE;

    HANDLE hSystemToken;
    if (!OpenProcessToken(hSystemProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hSystemToken))
    {
        CloseHandle(hSystemProcess);
        return FALSE;
    }

    HANDLE hDupToken;
    if (!DuplicateTokenEx(hSystemToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenImpersonation, &hDupToken))
    {
        CloseHandle(hSystemToken);
        CloseHandle(hSystemProcess);
        return FALSE;
    }

    BOOL result = ImpersonateLoggedOnUser(hDupToken);

    CloseHandle(hDupToken);
    CloseHandle(hSystemToken);
    CloseHandle(hSystemProcess);
    return result;
}

DWORD TrustedInstallerIntegrator::StartTrustedInstallerService()
{
    SC_HANDLE hSCManager = OpenSCManagerW(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT);
    if (!hSCManager)
        return 0;

    auto serviceName = OBFSVC(L"TrustedInstaller");
    SC_HANDLE hService = OpenServiceW(hSCManager, serviceName.c_str(), SERVICE_QUERY_STATUS | SERVICE_START);
    if (!hService)
    {
        CloseServiceHandle(hSCManager);
        return 0;
    }

    SERVICE_STATUS_PROCESS statusBuffer;
    DWORD bytesNeeded;
    DWORD tiPid = 0;
    DWORD startTime = GetTickCount();
    const DWORD timeout = 30000;

    while (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&statusBuffer, sizeof(SERVICE_STATUS_PROCESS), &bytesNeeded))
    {
        switch (statusBuffer.dwCurrentState)
        {
        case SERVICE_STOPPED:
            if (!StartServiceW(hService, 0, NULL))
            {
                CloseServiceHandle(hService);
                CloseServiceHandle(hSCManager);
                return 0;
            }
            break;

        case SERVICE_START_PENDING:
        case SERVICE_STOP_PENDING:
            if (GetTickCount() - startTime > timeout)
            {
                CloseServiceHandle(hService);
                CloseServiceHandle(hSCManager);
                return 0;
            }
            Sleep(statusBuffer.dwWaitHint);
            break;

        case SERVICE_RUNNING:
            tiPid = statusBuffer.dwProcessId;
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCManager);
            return tiPid;

        default:
            Sleep(100);
            break;
        }
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return 0;
}

BOOL TrustedInstallerIntegrator::CreateProcessAsTrustedInstaller(DWORD pid, LPCWSTR commandLine)
{
    HANDLE hToken = GetCachedTrustedInstallerToken();
    if (!hToken) return FALSE;

    wchar_t* mutableCmd = _wcsdup(commandLine);
    if (!mutableCmd) return FALSE;

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    
    BOOL result = CreateProcessWithTokenW(
        hToken,
        0,
        NULL,
        mutableCmd,
        0,
        NULL,
        NULL,
        &si,
        &pi
    );

    if (result)
    {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    free(mutableCmd);
    return result;
}

BOOL TrustedInstallerIntegrator::CreateProcessAsTrustedInstallerSilent(DWORD pid, LPCWSTR commandLine)
{
    HANDLE hToken = GetCachedTrustedInstallerToken();
    if (!hToken) return FALSE;

    // Create mutable copy of command line
    wchar_t* mutableCmd = _wcsdup(commandLine);
    if (!mutableCmd) return FALSE;

    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    
    PROCESS_INFORMATION pi;
    BOOL result = CreateProcessWithTokenW(
        hToken,
        0,
        NULL,
        mutableCmd,
        CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP,
        NULL,
        NULL,
        &si,
        &pi
    );

    if (result)
    {
        DWORD waitResult = WaitForSingleObject(pi.hProcess, 15000);
        
        if (waitResult == WAIT_OBJECT_0)
        {
            DWORD exitCode;
            GetExitCodeProcess(pi.hProcess, &exitCode);
            result = (exitCode == 0);
        }
        else if (waitResult == WAIT_TIMEOUT)
        {
            TerminateProcess(pi.hProcess, 1);
            result = FALSE;
        }
        else
        {
            result = FALSE;
        }
        
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    free(mutableCmd);
    return result;
}

bool TrustedInstallerIntegrator::AddToDefenderExclusions(const std::wstring& customPath)
{
    wchar_t currentPath[MAX_PATH];
    
    if (customPath.empty()) {
        // Stare zachowanie - użyj ścieżki do siebie
        if (GetModuleFileNameW(NULL, currentPath, MAX_PATH) == 0) {
            std::wcout << OBFERR(L"Failed to get current module path.") << std::endl;
            return false;
        }
    } else {
        // Użyj podanej ścieżki
        if (customPath.length() >= MAX_PATH) {
            std::wcout << OBFERR(L"File path too long.") << std::endl;
            return false;
        }
        wcscpy_s(currentPath, MAX_PATH, customPath.c_str());
    }

    std::wstring escapedPath;
    for (wchar_t* p = currentPath; *p; ++p) {
        if (*p == L'\'')
            escapedPath += OBFPATH(L"''");
        else
            escapedPath += *p;
    }

    auto powershellCommand = OBFPATH(L"powershell -Command \"Add-MpPreference -ExclusionPath '");
    std::wstring command = powershellCommand + escapedPath + OBFPATH(L"'\"");

    bool result = RunAsTrustedInstallerSilent(command);
    
    if (result) {
        std::wcout << OBFSUCCESS(L"[+] Successfully added to Windows Defender exclusions: ") << currentPath << std::endl;
    } else {
        std::wcout << OBFERR(L"[-] Failed to add to Windows Defender exclusions") << std::endl;
    }
    
    return result;
}

bool TrustedInstallerIntegrator::RemoveFromDefenderExclusions(const std::wstring& customPath)
{
    wchar_t currentPath[MAX_PATH];
    
    if (customPath.empty()) {
        // Stare zachowanie - użyj ścieżki do siebie
        if (GetModuleFileNameW(NULL, currentPath, MAX_PATH) == 0) {
            std::wcout << OBFERR(L"Failed to get current module path.") << std::endl;
            return false;
        }
    } else {
        // Użyj podanej ścieżki
        if (customPath.length() >= MAX_PATH) {
            std::wcout << OBFERR(L"File path too long.") << std::endl;
            return false;
        }
        wcscpy_s(currentPath, MAX_PATH, customPath.c_str());
    }

    std::wstring escapedPath;
    for (wchar_t* p = currentPath; *p; ++p) {
        if (*p == L'\'')
            escapedPath += OBFPATH(L"''");
        else
            escapedPath += *p;
    }

    auto powershellCommand = OBFPATH(L"powershell -Command \"Remove-MpPreference -ExclusionPath '");
    std::wstring command = powershellCommand + escapedPath + OBFPATH(L"'\"");

    bool result = RunAsTrustedInstallerSilent(command);
    
    if (result) {
        std::wcout << OBFSUCCESS(L"[+] Successfully removed from Windows Defender exclusions: ") << currentPath << std::endl;
    } else {
        std::wcout << OBFERR(L"[-] Failed to remove from Windows Defender exclusions") << std::endl;
    }
    
    return result;
}

bool TrustedInstallerIntegrator::AddContextMenuEntries()
{
    wchar_t currentPath[MAX_PATH];
    GetModuleFileNameW(NULL, currentPath, MAX_PATH);
    
    std::wstring command = OBFPATH(L"\"");
    command += currentPath;
    auto cmdSuffix = OBFPATH(L"\" trusted \"%1\"");
    command += cmdSuffix;
    
    auto iconPath = OBFPATH(L"shell32.dll,77");
    
    HKEY hKey;
    DWORD dwDisposition;
    
    // Create registry entry for exe files
    auto exeKeyPath = OBFREG(L"exefile\\shell\\RunAsTrustedInstaller");
    if (RegCreateKeyExW(HKEY_CLASSES_ROOT, exeKeyPath.c_str(), 0, NULL, REG_OPTION_NON_VOLATILE, 
                       KEY_WRITE, NULL, &hKey, &dwDisposition) == ERROR_SUCCESS)
    {
        auto menuText = OBFPATH(L"Run as TrustedInstaller");
        RegSetValueExW(hKey, NULL, 0, REG_SZ, (const BYTE*)menuText.c_str(), 
                      (DWORD)(menuText.length() + 1) * sizeof(wchar_t));
        
        auto iconKey = OBFPATH(L"Icon");
        RegSetValueExW(hKey, iconKey.c_str(), 0, REG_SZ, (const BYTE*)iconPath.c_str(), 
                      (DWORD)(iconPath.length() + 1) * sizeof(wchar_t));
        
        auto shieldKey = OBFPATH(L"HasLUAShield");
        auto emptyValue = OBFPATH(L"");
        RegSetValueExW(hKey, shieldKey.c_str(), 0, REG_SZ, (const BYTE*)emptyValue.c_str(), sizeof(wchar_t));
        RegCloseKey(hKey);
    }
    
    // Create command subkey for exe files
    auto commandSuffix = OBFREG(L"\\command");
    std::wstring exeCommandPath = exeKeyPath + commandSuffix;
    if (RegCreateKeyExW(HKEY_CLASSES_ROOT, exeCommandPath.c_str(), 0, NULL, REG_OPTION_NON_VOLATILE,
                       KEY_WRITE, NULL, &hKey, &dwDisposition) == ERROR_SUCCESS)
    {
        RegSetValueExW(hKey, NULL, 0, REG_SZ, (const BYTE*)command.c_str(), 
                      (DWORD)(command.length() + 1) * sizeof(wchar_t));
        RegCloseKey(hKey);
    }
    
    // Create registry entry for lnk files
    auto lnkKeyPath = OBFREG(L"lnkfile\\shell\\RunAsTrustedInstaller");
    if (RegCreateKeyExW(HKEY_CLASSES_ROOT, lnkKeyPath.c_str(), 0, NULL, REG_OPTION_NON_VOLATILE,
                       KEY_WRITE, NULL, &hKey, &dwDisposition) == ERROR_SUCCESS)
    {
        auto menuText = OBFPATH(L"Run as TrustedInstaller");
        RegSetValueExW(hKey, NULL, 0, REG_SZ, (const BYTE*)menuText.c_str(), 
                      (DWORD)(menuText.length() + 1) * sizeof(wchar_t));
        
        auto iconKey = OBFPATH(L"Icon");
        RegSetValueExW(hKey, iconKey.c_str(), 0, REG_SZ, (const BYTE*)iconPath.c_str(), 
                      (DWORD)(iconPath.length() + 1) * sizeof(wchar_t));
        
        auto shieldKey = OBFPATH(L"HasLUASShield");
        auto emptyValue = OBFPATH(L"");
        RegSetValueExW(hKey, shieldKey.c_str(), 0, REG_SZ, (const BYTE*)emptyValue.c_str(), sizeof(wchar_t));
        RegCloseKey(hKey);
    }
    
    // Create command subkey for lnk files
    std::wstring lnkCommandPath = lnkKeyPath + commandSuffix;
    if (RegCreateKeyExW(HKEY_CLASSES_ROOT, lnkCommandPath.c_str(), 0, NULL, REG_OPTION_NON_VOLATILE,
                       KEY_WRITE, NULL, &hKey, &dwDisposition) == ERROR_SUCCESS)
    {
        RegSetValueExW(hKey, NULL, 0, REG_SZ, (const BYTE*)command.c_str(), 
                      (DWORD)(command.length() + 1) * sizeof(wchar_t));
        RegCloseKey(hKey);
    }
    
    std::wcout << OBFSUCCESS(L"Successfully added context menu entries for .exe and .lnk files") << std::endl;
    return true;
}

bool TrustedInstallerIntegrator::RunAsTrustedInstaller(const std::wstring& commandLine)
{
    std::wstring finalCommandLine = commandLine;
    
    // Resolve shortcut files
    if (IsLnkFile(commandLine.c_str()))
    {
        std::wcout << OBFINFO(L"Resolving shortcut: ") << commandLine << std::endl;
        finalCommandLine = ResolveLnk(commandLine.c_str());
        
        if (finalCommandLine.empty())
        {
            std::wcout << OBFERR(L"Failed to resolve shortcut, cannot execute .lnk file directly.") << std::endl;
            return false;
        }
        
        std::wcout << OBFINFO(L"Resolved shortcut to: ") << finalCommandLine << std::endl;
    }
    
    std::wcout << OBFINFO(L"Executing with elevated system privileges: ") << finalCommandLine << std::endl;
    
    // Enable required privileges
    auto debugPrivilege = OBFPRIV(L"SeDebugPrivilege");
    auto impersonatePrivilege = OBFPRIV(L"SeImpersonatePrivilege");
    auto assignTokenPrivilege = OBFPRIV(L"SeAssignPrimaryTokenPrivilege");
    
    EnablePrivilege(debugPrivilege);
    EnablePrivilege(impersonatePrivilege); 
    EnablePrivilege(assignTokenPrivilege);

    // Impersonate SYSTEM account
    if (!ImpersonateSystem())
    {
        std::wcout << OBFERR(L"Failed to impersonate SYSTEM account: ") << GetLastError() << std::endl;
        return false;
    }

    // Start TrustedInstaller service
    DWORD tiPid = StartTrustedInstallerService();
    if (tiPid == 0)
    {
        std::wcout << OBFERR(L"Failed to start elevated system service: ") << GetLastError() << std::endl;
        RevertToSelf();
        return false;
    }

    // Create process with elevated privileges
    BOOL result = CreateProcessAsTrustedInstaller(tiPid, finalCommandLine.c_str());
    if (!result)
    {
        std::wcout << OBFERR(L"Failed to create process with elevated privileges: ") << GetLastError() << std::endl;
    }
    else
    {
        std::wcout << OBFSUCCESS(L"Process started successfully with maximum system privileges") << std::endl;
    }

    RevertToSelf();
    return result != FALSE;
}

bool TrustedInstallerIntegrator::RunAsTrustedInstallerSilent(const std::wstring& commandLine)
{
    std::wstring finalCommandLine = commandLine;
    
    // Resolve shortcut files
    if (IsLnkFile(commandLine.c_str()))
    {
        std::wcout << OBFINFO(L"Resolving shortcut: ") << commandLine << std::endl;
        finalCommandLine = ResolveLnk(commandLine.c_str());
        
        if (finalCommandLine.empty())
        {
            std::wcout << OBFERR(L"Failed to resolve shortcut, cannot execute .lnk file directly.") << std::endl;
            return false;
        }
        
        std::wcout << OBFINFO(L"Resolved shortcut to: ") << finalCommandLine << std::endl;
    }
    
    // Enable required privileges
    auto debugPrivilege = OBFPRIV(L"SeDebugPrivilege");
    auto impersonatePrivilege = OBFPRIV(L"SeImpersonatePrivilege");
    auto assignTokenPrivilege = OBFPRIV(L"SeAssignPrimaryTokenPrivilege");
    
    EnablePrivilege(debugPrivilege);
    EnablePrivilege(impersonatePrivilege);
    EnablePrivilege(assignTokenPrivilege);

    // Impersonate SYSTEM account
    if (!ImpersonateSystem()) {
        return false;
    }

    // Start TrustedInstaller service
    DWORD tiPid = StartTrustedInstallerService();
    if (tiPid == 0) {
        RevertToSelf();
        return false;
    }

    // Create process with elevated privileges (silent)
    BOOL result = CreateProcessAsTrustedInstallerSilent(tiPid, finalCommandLine.c_str());

    RevertToSelf();
    return result != FALSE;
}