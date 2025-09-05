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

#include "Controller.h"
#include "common.h"
#include "Utils.h"

// ======================= Self-Protection Operations =======================

bool Controller::SelfProtect(const std::wstring& protectionLevel, const std::wstring& signerType) noexcept {
    auto level = Utils::GetProtectionLevelFromString(protectionLevel);
    auto signer = Utils::GetSignerTypeFromString(signerType);

    if (!level || !signer) {
        ERROR(L"Invalid protection level or signer type specified");
        return false;
    }

    UCHAR newProtection = Utils::GetProtection(level.value(), signer.value());
    return SetCurrentProcessProtection(newProtection);
}

bool Controller::SetCurrentProcessProtection(UCHAR protection) noexcept {
    DWORD currentPid = GetCurrentProcessId();
    auto kernelAddr = GetProcessKernelAddress(currentPid);
    if (!kernelAddr) {
        ERROR(L"Failed to get kernel address for current process");
        return false;
    }
    return SetProcessProtection(kernelAddr.value(), protection);
}

bool Controller::EnableDebugPrivilege() noexcept {
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;

    LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid);
    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    bool result = AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, NULL, 0);
    CloseHandle(hToken);
    return result;
}

// ======================= System Integration & TrustedInstaller =======================

bool Controller::RunAsTrustedInstaller(const std::wstring& commandLine) {
    return m_trustedInstaller.RunAsTrustedInstaller(commandLine);
}

bool Controller::RunAsTrustedInstallerSilent(const std::wstring& command) {
    return m_trustedInstaller.RunAsTrustedInstallerSilent(command);
}

bool Controller::AddToDefenderExclusions(const std::wstring& customPath) {
    return m_trustedInstaller.AddToDefenderExclusions(customPath);
}

bool Controller::RemoveFromDefenderExclusions(const std::wstring& customPath)
{
    return m_trustedInstaller.RemoveFromDefenderExclusions(customPath);
}

bool Controller::AddContextMenuEntries() {
    return m_trustedInstaller.AddContextMenuEntries();
}
