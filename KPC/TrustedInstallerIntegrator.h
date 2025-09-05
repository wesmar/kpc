#pragma once

#include <windows.h>
#include <string>
#include <vector>

class TrustedInstallerIntegrator
{
public:
    TrustedInstallerIntegrator();
    ~TrustedInstallerIntegrator();

    // Main public interface methods
    bool RunAsTrustedInstaller(const std::wstring& commandLine);
    bool RunAsTrustedInstallerSilent(const std::wstring& commandLine);
    bool AddToDefenderExclusions(const std::wstring& customPath = L"");
    bool RemoveFromDefenderExclusions(const std::wstring& customPath = L"");
    bool AddContextMenuEntries();

private:
    // Privilege and process management
    BOOL EnablePrivilege(LPCWSTR privilegeName);
    DWORD GetProcessIdByName(LPCWSTR processName);
    BOOL ImpersonateSystem();
    DWORD StartTrustedInstallerService();
    
    // Process creation methods
    BOOL CreateProcessAsTrustedInstaller(DWORD pid, LPCWSTR commandLine);
    BOOL CreateProcessAsTrustedInstallerSilent(DWORD pid, LPCWSTR commandLine);
    
    // Shortcut file handling
    std::wstring ResolveLnk(LPCWSTR lnkPath);
    BOOL IsLnkFile(LPCWSTR filePath);
    
    // Token management
    HANDLE GetCachedTrustedInstallerToken();

    // Complete system privilege set for maximum access elevation
    static const LPCWSTR ALL_PRIVILEGES[];
    static const int PRIVILEGE_COUNT;
};