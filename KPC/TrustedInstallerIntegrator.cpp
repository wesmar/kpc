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
#include "common.h"  // Added missing include for obfuscation macros
#include <tchar.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <objbase.h>
#include <iostream>
#include <algorithm>
#include <cctype>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shell32.lib")

// Complete system privilege set for maximum access elevation
const LPCWSTR TrustedInstallerIntegrator::ALL_PRIVILEGES[] = {
    SE_ASSIGNPRIMARYTOKEN_NAME,     // Assign primary token to process
    SE_BACKUP_NAME,                 // Backup files and directories
    SE_RESTORE_NAME,                // Restore files and directories
    SE_DEBUG_NAME,                  // Debug processes
    SE_IMPERSONATE_NAME,            // Impersonate client after authentication
    SE_TAKE_OWNERSHIP_NAME,         // Take ownership of files/objects
    SE_LOAD_DRIVER_NAME,            // Load and unload device drivers
    SE_SYSTEM_ENVIRONMENT_NAME,     // Modify system environment variables
    SE_MANAGE_VOLUME_NAME,          // Manage volume and disk quotas
    SE_SECURITY_NAME,               // Manage security and audit logs
    SE_SHUTDOWN_NAME,               // Shut down the system
    SE_SYSTEMTIME_NAME,             // Change system time
    SE_TCB_NAME,                    // Act as part of operating system
    SE_INCREASE_QUOTA_NAME,         // Increase process quotas
    SE_AUDIT_NAME,                  // Generate security audits
    SE_CHANGE_NOTIFY_NAME,          // Bypass traverse checking
    SE_UNDOCK_NAME,                 // Remove computer from docking station
    SE_CREATE_TOKEN_NAME,           // Create access tokens
    SE_LOCK_MEMORY_NAME,            // Lock pages in memory
    SE_CREATE_PAGEFILE_NAME,        // Create page files
    SE_CREATE_PERMANENT_NAME,       // Create permanent shared objects
    SE_SYSTEM_PROFILE_NAME,         // Profile system performance
    SE_PROF_SINGLE_PROCESS_NAME,    // Profile single process
    SE_CREATE_GLOBAL_NAME,          // Create global objects
    SE_TIME_ZONE_NAME,              // Change time zone
    SE_CREATE_SYMBOLIC_LINK_NAME,   // Create symbolic links
    L"SeIncreaseBasePriorityPrivilege",  // Direct string instead of OBFPRIV
    L"SeRemoteShutdownPrivilege",        // Direct string instead of OBFPRIV  
    L"SeIncreaseWorkingSetPrivilege"     // Direct string instead of OBFPRIV
};

// Corrected array size calculation
const int TrustedInstallerIntegrator::PRIVILEGE_COUNT = sizeof(ALL_PRIVILEGES) / sizeof(LPCWSTR);

TrustedInstallerIntegrator::TrustedInstallerIntegrator()
{
    // Initialize COM for shell operations and shortcut resolution
    CoInitialize(NULL);
}

TrustedInstallerIntegrator::~TrustedInstallerIntegrator()
{
    // Cleanup COM resources
    CoUninitialize();
}

// ======================= Shortcut File Detection & Resolution =======================

BOOL TrustedInstallerIntegrator::IsLnkFile(LPCWSTR filePath)
{
    if (!filePath || wcslen(filePath) < 4) 
        return FALSE;
    
    // Check for .lnk extension (case insensitive comparison)
    std::wstring path(filePath);
    std::transform(path.begin(), path.end(), path.begin(), ::towlower);
    
    auto lnkExt = OBFPATH(L".lnk");
    std::wstring lowerLnkExt = lnkExt;
    std::transform(lowerLnkExt.begin(), lowerLnkExt.end(), lowerLnkExt.begin(), ::towlower);
    
    return path.find(lowerLnkExt) != std::wstring::npos && 
           path.rfind(lowerLnkExt) == path.length() - lowerLnkExt.length();
}

std::wstring TrustedInstallerIntegrator::ResolveLnk(LPCWSTR lnkPath)
{
    std::wstring result;
    IShellLinkW* psl = nullptr;
    IPersistFile* ppf = nullptr;
    
    // Verify shortcut file exists before processing
    if (GetFileAttributesW(lnkPath) == INVALID_FILE_ATTRIBUTES)
    {
        std::wcout << L"Shortcut file does not exist: " << lnkPath << std::endl;
        return result;
    }

    // Create Shell Link COM object for shortcut resolution
    HRESULT hres = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLinkW, (LPVOID*)&psl);
    if (FAILED(hres))
    {
        std::wcout << L"Failed to create ShellLink instance: 0x" << std::hex << hres << std::endl;
        return result;
    }

    // Get IPersistFile interface for loading shortcut data
    hres = psl->QueryInterface(IID_IPersistFile, (LPVOID*)&ppf);
    if (FAILED(hres))
    {
        std::wcout << L"Failed to get IPersistFile interface: 0x" << std::hex << hres << std::endl;
        psl->Release();
        return result;
    }

    // Load the shortcut file and extract information
    hres = ppf->Load(lnkPath, STGM_READ);
    if (FAILED(hres))
    {
        std::wcout << L"Failed to load shortcut file: 0x" << std::hex << hres << std::endl;
        ppf->Release();
        psl->Release();
        return result;
    }

    // Extract target path from shortcut
    wchar_t targetPath[MAX_PATH * 2] = {0};
    WIN32_FIND_DATAW wfd = {0};
    
    hres = psl->GetPath(targetPath, MAX_PATH * 2, &wfd, SLGP_RAWPATH);
    if (FAILED(hres))
    {
        std::wcout << L"Failed to get shortcut target path: 0x" << std::hex << hres << std::endl;
    }
    else if (wcslen(targetPath) > 0)
    {
        result = targetPath;
        
        // Append command line arguments if they exist
        wchar_t args[MAX_PATH * 2] = {0};
        hres = psl->GetArguments(args, MAX_PATH * 2);
        if (SUCCEEDED(hres) && wcslen(args) > 0)
        {
            result += L" ";
            result += args;
        }
    }

    // Cleanup COM objects
    ppf->Release();
    psl->Release();
    
    // Fallback to original path if resolution failed
    if (result.empty()) {
        result = lnkPath;
    }
    
    return result;
}

// ======================= Privilege Management System =======================

BOOL TrustedInstallerIntegrator::EnablePrivilege(LPCWSTR privilegeName)
{
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken))
        return FALSE;

    // Lookup privilege LUID for the specified privilege
    LUID luid;
    if (!LookupPrivilegeValueW(NULL, privilegeName, &luid))
    {
        CloseHandle(hToken);
        return FALSE;
    }

    // Enable the requested privilege
    TOKEN_PRIVILEGES tp = { 0 };
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL result = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
    CloseHandle(hToken);
    
    // Verify privilege was actually enabled (not just the call succeeded)
    return result && (GetLastError() == ERROR_SUCCESS);
}

// ======================= Process Enumeration & Discovery =======================

DWORD TrustedInstallerIntegrator::GetProcessIdByName(LPCWSTR processName)
{
    // Create system process snapshot for enumeration
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return 0;

    DWORD pid = 0;
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);

    // Iterate through all running processes to find match
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
// ======================= System Token Impersonation =======================

BOOL TrustedInstallerIntegrator::ImpersonateSystem()
{
    // Find winlogon.exe process (runs as SYSTEM account)
    auto winlogonProcess = OBFPROC(L"winlogon.exe");
    DWORD systemPid = GetProcessIdByName(winlogonProcess.c_str());
    if (systemPid == 0)
        return FALSE;

    // Open winlogon process for token duplication access
    HANDLE hSystemProcess = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, systemPid);
    if (!hSystemProcess)
        return FALSE;

    // Extract SYSTEM token from winlogon process
    HANDLE hSystemToken;
    if (!OpenProcessToken(hSystemProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hSystemToken))
    {
        CloseHandle(hSystemProcess);
        return FALSE;
    }

    // Duplicate token for impersonation with elevated privileges
    HANDLE hDupToken;
    if (!DuplicateTokenEx(hSystemToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenImpersonation, &hDupToken))
    {
        CloseHandle(hSystemToken);
        CloseHandle(hSystemProcess);
        return FALSE;
    }

    // Impersonate SYSTEM user context for elevated operations
    BOOL result = ImpersonateLoggedOnUser(hDupToken);

    // Cleanup allocated handles
    CloseHandle(hDupToken);
    CloseHandle(hSystemToken);
    CloseHandle(hSystemProcess);
    return result;
}

// ======================= Enhanced Service Management =======================

DWORD TrustedInstallerIntegrator::StartTrustedInstallerService()
{
    // Open service control manager with appropriate permissions
    SC_HANDLE hSCManager = OpenSCManagerW(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT);
    if (!hSCManager)
        return 0;

    // Open the privileged system service using obfuscated name
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
    const DWORD timeout = 30000; // 30 second service startup timeout

    // Monitor service status with timeout protection
    while (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&statusBuffer, sizeof(SERVICE_STATUS_PROCESS), &bytesNeeded))
    {
        switch (statusBuffer.dwCurrentState)
        {
        case SERVICE_STOPPED:
            // Service is stopped - attempt to start it
            if (!StartServiceW(hService, 0, NULL))
            {
                CloseServiceHandle(hService);
                CloseServiceHandle(hSCManager);
                return 0;
            }
            break;

        case SERVICE_START_PENDING:
        case SERVICE_STOP_PENDING:
            // Service is transitioning - wait with timeout protection
            if (GetTickCount() - startTime > timeout)
            {
                CloseServiceHandle(hService);
                CloseServiceHandle(hSCManager);
                return 0; // Timeout reached
            }
            Sleep(statusBuffer.dwWaitHint);
            break;

        case SERVICE_RUNNING:
            // Service is active - extract PID and return
            tiPid = statusBuffer.dwProcessId;
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCManager);
            return tiPid;

        default:
            // Unknown service state - brief wait before retry
            Sleep(100);
            break;
        }
    }

    // Service management failed - cleanup handles
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return 0;
}

// ======================= Process Creation with Elevated Token =======================

BOOL TrustedInstallerIntegrator::CreateProcessAsTrustedInstaller(DWORD pid, LPCWSTR commandLine)
{
    // Open target service process for token extraction
    HANDLE hTIProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hTIProcess)
        return FALSE;

    // Extract elevated system token for privilege escalation
    HANDLE hTIToken;
    if (!OpenProcessToken(hTIProcess, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hTIToken))
    {
        CloseHandle(hTIProcess);
        return FALSE;
    }

    // Duplicate token for impersonation with maximum access rights
    HANDLE hDupToken;
    if (!DuplicateTokenEx(hTIToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenImpersonation, &hDupToken))
    {
        CloseHandle(hTIToken);
        CloseHandle(hTIProcess);
        return FALSE;
    }

    // Enable comprehensive system privilege set on duplicated token
    // This grants maximum possible access rights for system-level operations
    for (int i = 0; i < PRIVILEGE_COUNT; i++)
    {
        TOKEN_PRIVILEGES tp;
        LUID luid;

        if (LookupPrivilegeValueW(NULL, ALL_PRIVILEGES[i], &luid))
        {
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(hDupToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
        }
    }

    // Create mutable command line copy (required by CreateProcessWithTokenW API)
    wchar_t* mutableCmd = _wcsdup(commandLine);
    if (!mutableCmd)
    {
        CloseHandle(hDupToken);
        CloseHandle(hTIToken);
        CloseHandle(hTIProcess);
        return FALSE;
    }

    // Configure process startup for interactive user execution
    // Allow normal console and window behavior for user commands
    STARTUPINFOW si = { sizeof(si) };
    
    PROCESS_INFORMATION pi;
    BOOL result = CreateProcessWithTokenW(
        hDupToken,                      // Use elevated impersonation token
        0,                              // No profile loading for faster startup
        NULL,                           // Use command line for executable resolution
        mutableCmd,                     // Mutable command line string
        0,                              // No special creation flags - allow normal behavior
        NULL,                           // Inherit current environment variables
        NULL,                           // Use current working directory
        &si,                            // Startup configuration
        &pi                             // Process information output
    );

    if (result)
    {
        // For interactive commands, don't wait - allow independent execution
        // This enables cmd, powershell, etc. to remain open for user interaction
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    // Cleanup all allocated resources
    free(mutableCmd);
    CloseHandle(hDupToken);
    CloseHandle(hTIToken);
    CloseHandle(hTIProcess);
    
    return result;
}
// ======================= Silent Process Creation for System Operations =======================

BOOL TrustedInstallerIntegrator::CreateProcessAsTrustedInstallerSilent(DWORD pid, LPCWSTR commandLine)
{
    // Open service process for elevated token access
    HANDLE hTIProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hTIProcess) 
        return FALSE;

    // Extract elevated system token for privilege escalation
    HANDLE hTIToken;
    if (!OpenProcessToken(hTIProcess, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hTIToken))
    {
        CloseHandle(hTIProcess);
        return FALSE;
    }

    // Duplicate token for impersonation with maximum privileges
    HANDLE hDupToken;
    if (!DuplicateTokenEx(hTIToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenImpersonation, &hDupToken))
    {
        CloseHandle(hTIToken);
        CloseHandle(hTIProcess);
        return FALSE;
    }

    // Enable comprehensive system privilege set on duplicated token
    // This grants maximum possible access rights for system operations
    for (int i = 0; i < PRIVILEGE_COUNT; i++)
    {
        TOKEN_PRIVILEGES tp;
        LUID luid;
        
        if (LookupPrivilegeValueW(NULL, ALL_PRIVILEGES[i], &luid))
        {
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(hDupToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
        }
    }

    // Create mutable command line copy (required by CreateProcessWithTokenW)
    wchar_t* mutableCmd = _wcsdup(commandLine);
    if (!mutableCmd)
    {
        CloseHandle(hDupToken);
        CloseHandle(hTIToken);
        CloseHandle(hTIProcess);
        return FALSE;
    }

    // Configure process startup for completely silent execution
    // No windows, no console output, no user interaction
    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;  // Control window visibility only
    si.wShowWindow = SW_HIDE;           // Hide all windows completely
    
    PROCESS_INFORMATION pi;
    BOOL result = CreateProcessWithTokenW(
        hDupToken,                       // Use elevated impersonation token
        0,                              // No profile loading (faster startup)
        NULL,                           // Use command line for executable resolution
        mutableCmd,                     // Mutable command line string
        CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP,  // Hidden execution, isolated process group
        NULL,                           // Inherit environment variables
        NULL,                           // Use current directory
        &si,                            // Startup configuration
        &pi                             // Process information output
    );

    if (result)
    {
        // Wait for process completion with timeout for system operations
        // Silent operations should complete quickly (file copy, registry modifications, etc.)
        DWORD waitResult = WaitForSingleObject(pi.hProcess, 15000);  // 15 second timeout
        
        if (waitResult == WAIT_OBJECT_0)
        {
            // Process completed successfully - check exit code
            DWORD exitCode;
            GetExitCodeProcess(pi.hProcess, &exitCode);
            result = (exitCode == 0);  // Success only if exit code is 0
        }
        else if (waitResult == WAIT_TIMEOUT)
        {
            // Process exceeded timeout - terminate forcefully
            TerminateProcess(pi.hProcess, 1);
            result = FALSE;
        }
        else
        {
            // Wait operation failed for other reasons
            result = FALSE;
        }
        
        // Cleanup process handles
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    // Cleanup all allocated resources
    free(mutableCmd);
    CloseHandle(hDupToken);
    CloseHandle(hTIToken);
    CloseHandle(hTIProcess);
    
    return result;
}

// ======================= Windows Defender Exclusion Management =======================

bool TrustedInstallerIntegrator::AddToDefenderExclusions()
{
    HKEY hKey;
    auto defenderSubKey = OBFREG(L"SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths");
    
    // Get current executable path for exclusion
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(NULL, path, MAX_PATH);

    // Attempt to open Windows Defender exclusions registry key
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, defenderSubKey.c_str(), 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS)
    {
        // Add executable path as exclusion (value 0 = excluded from scanning)
        DWORD exclusionValue = 0;
        if (RegSetValueExW(hKey, path, 0, REG_DWORD, (const BYTE*)&exclusionValue, sizeof(DWORD)) == ERROR_SUCCESS)
        {
            std::wcout << L"Successfully added to Windows Defender exclusions: " << path << std::endl;
            RegCloseKey(hKey);
            return true;
        }
        RegCloseKey(hKey);
    }
    
    std::wcout << L"Failed to add Windows Defender exclusion - insufficient privileges or registry access denied" << std::endl;
    return false;
}

// ======================= Context Menu Integration System =======================

bool TrustedInstallerIntegrator::AddContextMenuEntries()
{
    // Get current executable path for context menu command construction
    wchar_t currentPath[MAX_PATH];
    GetModuleFileNameW(NULL, currentPath, MAX_PATH);
    
    // Construct command template for context menu execution
    // %1 parameter will be replaced with the selected file path
    std::wstring command = L"\"";
    command += currentPath;
    auto cmdSuffix = OBFPATH(L"\" trusted \"%1\"");
    command += cmdSuffix;
    
    // Use Windows shield icon for elevated context menu entries
    auto iconPath = OBFPATH(L"shell32.dll,77");  // Shield icon resource
    
    HKEY hKey;
    DWORD dwDisposition;
    
    // ======================= .exe File Context Menu Registration =======================
    auto exeKeyPath = OBFREG(L"exefile\\shell\\RunAsTrustedInstaller");
    // Registry key creation with proper parameters
    if (RegCreateKeyExW(HKEY_CLASSES_ROOT, exeKeyPath.c_str(), 0, NULL, REG_OPTION_NON_VOLATILE, 
                       KEY_WRITE, NULL, &hKey, &dwDisposition) == ERROR_SUCCESS)
    {
        // Set context menu display text and icon
        auto menuText = OBFPATH(L"Run as TrustedInstaller");
        // RegSetValueExW with proper parameters
        RegSetValueExW(hKey, NULL, 0, REG_SZ, (const BYTE*)menuText.c_str(), 
                      (DWORD)(menuText.length() + 1) * sizeof(wchar_t));
        
        RegSetValueExW(hKey, L"Icon", 0, REG_SZ, (const BYTE*)iconPath.c_str(), 
                      (DWORD)(iconPath.length() + 1) * sizeof(wchar_t));
        
        // Add UAC shield indicator for elevated operations
        RegSetValueExW(hKey, L"HasLUAShield", 0, REG_SZ, (const BYTE*)L"", sizeof(wchar_t));
        RegCloseKey(hKey);
    }
    
    // Set command execution string for .exe files
    auto commandSuffix = OBFREG(L"\\command");
    std::wstring exeCommandPath = exeKeyPath + commandSuffix;
    if (RegCreateKeyExW(HKEY_CLASSES_ROOT, exeCommandPath.c_str(), 0, NULL, REG_OPTION_NON_VOLATILE,
                       KEY_WRITE, NULL, &hKey, &dwDisposition) == ERROR_SUCCESS)
    {
        RegSetValueExW(hKey, NULL, 0, REG_SZ, (const BYTE*)command.c_str(), 
                      (DWORD)(command.length() + 1) * sizeof(wchar_t));
        RegCloseKey(hKey);
    }
    
    // ======================= .lnk File Context Menu Registration =======================
    auto lnkKeyPath = OBFREG(L"lnkfile\\shell\\RunAsTrustedInstaller");
    if (RegCreateKeyExW(HKEY_CLASSES_ROOT, lnkKeyPath.c_str(), 0, NULL, REG_OPTION_NON_VOLATILE,
                       KEY_WRITE, NULL, &hKey, &dwDisposition) == ERROR_SUCCESS)
    {
        // Set context menu display text and icon for shortcuts
        auto menuText = OBFPATH(L"Run as TrustedInstaller");
        RegSetValueExW(hKey, NULL, 0, REG_SZ, (const BYTE*)menuText.c_str(), 
                      (DWORD)(menuText.length() + 1) * sizeof(wchar_t));
        
        RegSetValueExW(hKey, L"Icon", 0, REG_SZ, (const BYTE*)iconPath.c_str(), 
                      (DWORD)(iconPath.length() + 1) * sizeof(wchar_t));
        
        // Add UAC shield indicator for elevated operations
        RegSetValueExW(hKey, L"HasLUAShield", 0, REG_SZ, (const BYTE*)L"", sizeof(wchar_t));
        RegCloseKey(hKey);
    }
    
    // Set command execution string for .lnk files
    std::wstring lnkCommandPath = lnkKeyPath + commandSuffix;
    if (RegCreateKeyExW(HKEY_CLASSES_ROOT, lnkCommandPath.c_str(), 0, NULL, REG_OPTION_NON_VOLATILE,
                       KEY_WRITE, NULL, &hKey, &dwDisposition) == ERROR_SUCCESS)
    {
        RegSetValueExW(hKey, NULL, 0, REG_SZ, (const BYTE*)command.c_str(), 
                      (DWORD)(command.length() + 1) * sizeof(wchar_t));
        RegCloseKey(hKey);
    }
    
    std::wcout << L"Successfully added context menu entries for .exe and .lnk files" << std::endl;
    return true;
}

// ======================= Main Elevated Execution Interface =======================

bool TrustedInstallerIntegrator::RunAsTrustedInstaller(const std::wstring& commandLine)
{
    std::wstring finalCommandLine = commandLine;
    
    // Check if input is a shortcut file and resolve target if necessary
    if (IsLnkFile(commandLine.c_str()))
    {
        std::wcout << L"Resolving shortcut: " << commandLine << std::endl;
        finalCommandLine = ResolveLnk(commandLine.c_str());
        
        if (finalCommandLine.empty())
        {
            std::wcout << L"Failed to resolve shortcut, using original command" << std::endl;
            finalCommandLine = commandLine;
        }
        else
        {
            std::wcout << L"Resolved shortcut to: " << finalCommandLine << std::endl;
        }
    }
    
    std::wcout << L"Executing with elevated system privileges: " << finalCommandLine << std::endl;
    
    // Enable essential privileges for token manipulation and impersonation
    EnablePrivilege(SE_DEBUG_NAME);
    EnablePrivilege(SE_IMPERSONATE_NAME); 
    EnablePrivilege(SE_ASSIGNPRIMARYTOKEN_NAME);

    // Impersonate SYSTEM account for elevated service access
    if (!ImpersonateSystem())
    {
        std::wcout << L"Failed to impersonate SYSTEM account: " << GetLastError() << std::endl;
        return false;
    }

    // Start the elevated system service and obtain process identifier
    DWORD tiPid = StartTrustedInstallerService();
    if (tiPid == 0)
    {
        std::wcout << L"Failed to start elevated system service: " << GetLastError() << std::endl;
        RevertToSelf();
        return false;
    }

    // Create process using elevated system service token
    BOOL result = CreateProcessAsTrustedInstaller(tiPid, finalCommandLine.c_str());
    if (!result)
    {
        std::wcout << L"Failed to create process with elevated privileges: " << GetLastError() << std::endl;
    }
    else
    {
        std::wcout << L"Process started successfully with maximum system privileges" << std::endl;
    }

    // Revert to original security context
    RevertToSelf();
    return result != FALSE;
}

bool TrustedInstallerIntegrator::RunAsTrustedInstallerSilent(const std::wstring& commandLine)
{
    // Enable essential privileges for elevated token operations
    EnablePrivilege(SE_DEBUG_NAME);
    EnablePrivilege(SE_IMPERSONATE_NAME);
    EnablePrivilege(SE_ASSIGNPRIMARYTOKEN_NAME);

    // Impersonate SYSTEM account for service access (silent mode)
    if (!ImpersonateSystem()) {
        return false;
    }

    // Start elevated system service and obtain process identifier (silent mode)
    DWORD tiPid = StartTrustedInstallerService();
    if (tiPid == 0) {
        RevertToSelf();
        return false;
    }

    // Create process using elevated service token (silent execution mode)
    BOOL result = CreateProcessAsTrustedInstallerSilent(tiPid, commandLine.c_str());

    // Revert to original security context
    RevertToSelf();
    return result != FALSE;
}
