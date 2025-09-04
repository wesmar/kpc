#pragma once

#include <windows.h>
#include <string>
#include <vector>

class TrustedInstallerIntegrator
{
public:
    TrustedInstallerIntegrator();
    ~TrustedInstallerIntegrator();

    bool RunAsTrustedInstaller(const std::wstring& commandLine);
    bool RunAsTrustedInstallerSilent(const std::wstring& commandLine);
    bool AddToDefenderExclusions();
    bool AddContextMenuEntries();

private:
    // Private helper methods
    BOOL EnablePrivilege(LPCWSTR privilegeName);
    DWORD GetProcessIdByName(LPCWSTR processName);
    BOOL ImpersonateSystem();
    DWORD StartTrustedInstallerService();
    BOOL CreateProcessAsTrustedInstaller(DWORD pid, LPCWSTR commandLine);
    std::wstring ResolveLnk(LPCWSTR lnkPath);
    BOOL IsLnkFile(LPCWSTR filePath);
    BOOL CreateProcessAsTrustedInstallerSilent(DWORD pid, LPCWSTR commandLine);

    // Complete system privilege list - Properly declared as static const
    static const LPCWSTR ALL_PRIVILEGES[];
    static const int PRIVILEGE_COUNT;
};
