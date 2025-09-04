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

#include "Utils.h"
#include "common.h"
#include <psapi.h>
#include <tlhelp32.h>
#include <unordered_map>
#include <unordered_set>
#include <algorithm>
#include <cctype>

#pragma comment(lib, "psapi.lib")

namespace Utils
{
    // ======================= Kernel Base Address Resolution =======================
    std::optional<ULONG_PTR> GetKernelBaseAddress() noexcept
    {
        LPVOID drivers[1024];
        DWORD cbNeeded;
        
        // Enumerate all loaded kernel drivers
        if (!EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded))
            return std::nullopt;

        // First driver entry is always ntoskrnl.exe (kernel base address)
        return reinterpret_cast<ULONG_PTR>(drivers[0]);
    }

    // ======================= Enhanced Process Name Resolution =======================
    std::wstring GetProcessName(DWORD pid) noexcept
    {
        if (pid == 0)
            return OBFPROC(L"System Idle Process");
        if (pid == 4)
            return OBFPROC(L"System [NT Kernel Core]");

        // Known system PIDs with obfuscated names to avoid static detection
        static const std::unordered_map<DWORD, std::wstring> knownSystemPids = {
            {188, OBFPROC(L"Secure System")},
            {232, OBFPROC(L"Registry")}, 
            {3052, OBFPROC(L"Memory Compression")},
            {3724, OBFPROC(L"Memory Manager")},
            {256, OBFPROC(L"VSM Process")},
            {264, OBFPROC(L"VBS Process")},
            {288, OBFPROC(L"Font Driver Host")},
            {296, OBFPROC(L"User Mode Driver Host")}
        };

        if (auto it = knownSystemPids.find(pid); it != knownSystemPids.end()) {
            return it->second;
        }

        // Method 1: Direct process handle with extended access rights
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!hProcess) {
            // Fallback: Try with minimal permissions for system processes
            hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        }
        
        if (hProcess) {
            wchar_t processName[MAX_PATH] = {0};
            DWORD size = MAX_PATH;
            
            // Try QueryFullProcessImageName first (most reliable)
            if (QueryFullProcessImageNameW(hProcess, 0, processName, &size)) {
                std::wstring fullPath(processName);
                size_t lastSlash = fullPath.find_last_of(L'\\');
                if (lastSlash != std::wstring::npos) {
                    CloseHandle(hProcess);
                    return fullPath.substr(lastSlash + 1);
                }
            }

            // Fallback: Try GetProcessImageFileName for system processes
            if (GetProcessImageFileNameW(hProcess, processName, MAX_PATH)) {
                std::wstring fullPath(processName);
                size_t lastSlash = fullPath.find_last_of(L'\\');
                if (lastSlash != std::wstring::npos) {
                    CloseHandle(hProcess);
                    return fullPath.substr(lastSlash + 1);
                }
            }
            CloseHandle(hProcess);
        }

        // Method 2: Process snapshot enumeration (most reliable for protected processes)
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe;
            pe.dwSize = sizeof(PROCESSENTRY32W);
            
            if (Process32FirstW(hSnapshot, &pe)) {
                do {
                    if (pe.th32ProcessID == pid) {
                        CloseHandle(hSnapshot);
                        return std::wstring(pe.szExeFile);
                    }
                } while (Process32NextW(hSnapshot, &pe));
            }
            CloseHandle(hSnapshot);
        }

        // Unable to resolve process name
        return OBFPROC(L"[Unknown]");
    }

    // ======================= Protection Level String Conversion =======================
    const wchar_t* GetProtectionLevelAsString(UCHAR protectionLevel) noexcept
    {
        switch (static_cast<PS_PROTECTED_TYPE>(protectionLevel))
        {
            case PS_PROTECTED_TYPE::None:           return L"None";
            case PS_PROTECTED_TYPE::ProtectedLight: return L"PPL";
            case PS_PROTECTED_TYPE::Protected:      return L"PP";
            default:                                return L"Unknown";
        }
    }

    const wchar_t* GetSignerTypeAsString(UCHAR signerType) noexcept
    {
        switch (static_cast<PS_PROTECTED_SIGNER>(signerType))
        {
            case PS_PROTECTED_SIGNER::None:         return L"None";
            case PS_PROTECTED_SIGNER::Authenticode: return L"Authenticode";
            case PS_PROTECTED_SIGNER::CodeGen:      return L"CodeGen";
            case PS_PROTECTED_SIGNER::Antimalware:  return L"Antimalware";
            case PS_PROTECTED_SIGNER::Lsa:          return L"Lsa";
            case PS_PROTECTED_SIGNER::Windows:      return L"Windows";
            case PS_PROTECTED_SIGNER::WinTcb:       return L"WinTcb";
            case PS_PROTECTED_SIGNER::WinSystem:    return L"WinSystem";
            case PS_PROTECTED_SIGNER::App:          return L"App";
            default:                                return L"Unknown";
        }
    }

    const wchar_t* GetSignatureLevelAsString(UCHAR signatureLevel) noexcept
    {
        // Comprehensive signature level mapping for modern Windows versions
        static const std::unordered_map<UCHAR, const wchar_t*> signatureLevels = {
            {0x00, L"Unchecked"},        // No signature verification
            {0x01, L"Unsigned"},         // Unsigned binary
            {0x02, L"Enterprise"},       // Enterprise certificate
            {0x03, L"Custom1"},          // Custom verification level 1
            {0x04, L"Authenticode"},     // Standard Authenticode signature
            {0x05, L"Custom2"},          // Custom verification level 2
            {0x06, L"Store"},            // Microsoft Store application
            {0x07, L"Antimalware"},      // Antimalware vendor signature
            {0x08, L"Microsoft"},        // Microsoft corporation signature
            {0x09, L"Custom4"},          // Custom verification level 4
            {0x0A, L"Custom5"},          // Custom verification level 5
            {0x0B, L"Dynamic"},          // Dynamically generated signature
            {0x0C, L"Windows"},          // Windows component signature
            {0x0D, L"WinTcb"},           // Windows Trusted Computing Base
            {0x0E, L"WinSystem"},        // Windows System signature
            {0x0F, L"App"},              // Application signature
            // Extended signature levels for newer Windows versions
            {0x10, L"Custom6"},          {0x11, L"Custom7"},          {0x12, L"Custom8"},
            {0x13, L"Custom9"},          {0x14, L"Custom10"},         {0x15, L"DevUnlock"},
            {0x16, L"Custom11"},         {0x17, L"Custom12"},         {0x18, L"Custom13"},
            {0x19, L"Custom14"},         {0x1A, L"Custom15"},         {0x1B, L"StoreApp"},
            {0x1C, L"WSL"},              {0x1D, L"None2"},            {0x1E, L"WinTcb2"},
            {0x1F, L"WinSystemHigh"},    {0x20, L"PplLight"},         {0x21, L"PplMedium"},
            {0x22, L"PplHigh"},
            // High-level system signatures (0x30+ range)
            {0x30, L"SystemLight"},      {0x31, L"SystemMedium"},     {0x32, L"SystemHigh"},
            {0x33, L"SystemCritical"},   {0x34, L"KernelLight"},      {0x35, L"KernelMedium"},
            {0x36, L"KernelHigh"},       {0x37, L"KernelCritical"},   {0x38, L"HypervisorLight"},
            {0x39, L"HypervisorMedium"}, {0x3A, L"HypervisorHigh"},   {0x3B, L"HypervisorCritical"},
            {0x3C, L"VbsLight"},         {0x3D, L"VbsMedium"},        {0x3E, L"VbsHigh"},
            {0x3F, L"VbsCritical"}
        };

        auto it = signatureLevels.find(signatureLevel);
        return (it != signatureLevels.end()) ? it->second : L"Reserved";
    }

    // ======================= Protection Level Parsing =======================
    std::optional<UCHAR> GetProtectionLevelFromString(const std::wstring& protectionLevel) noexcept
    {
        static const std::unordered_map<std::wstring, UCHAR> levels = {
            {L"none", static_cast<UCHAR>(PS_PROTECTED_TYPE::None)},
            {L"ppl", static_cast<UCHAR>(PS_PROTECTED_TYPE::ProtectedLight)},
            {L"pp", static_cast<UCHAR>(PS_PROTECTED_TYPE::Protected)}
        };

        // Convert to lowercase for case-insensitive matching
        std::wstring lower = protectionLevel;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);

        auto it = levels.find(lower);
        return (it != levels.end()) ? std::make_optional(it->second) : std::nullopt;
    }

    std::optional<UCHAR> GetSignerTypeFromString(const std::wstring& signerType) noexcept
    {
        static const std::unordered_map<std::wstring, UCHAR> signers = {
            {L"none", static_cast<UCHAR>(PS_PROTECTED_SIGNER::None)},
            {L"authenticode", static_cast<UCHAR>(PS_PROTECTED_SIGNER::Authenticode)},
            {L"codegen", static_cast<UCHAR>(PS_PROTECTED_SIGNER::CodeGen)},
            {L"antimalware", static_cast<UCHAR>(PS_PROTECTED_SIGNER::Antimalware)},
            {L"lsa", static_cast<UCHAR>(PS_PROTECTED_SIGNER::Lsa)},
            {L"windows", static_cast<UCHAR>(PS_PROTECTED_SIGNER::Windows)},
            {L"wintcb", static_cast<UCHAR>(PS_PROTECTED_SIGNER::WinTcb)},
            {L"winsystem", static_cast<UCHAR>(PS_PROTECTED_SIGNER::WinSystem)},
            {L"app", static_cast<UCHAR>(PS_PROTECTED_SIGNER::App)}
        };

        // Convert to lowercase for case-insensitive matching
        std::wstring lower = signerType;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);

        auto it = signers.find(lower);
        return (it != signers.end()) ? std::make_optional(it->second) : std::nullopt;
    }

    // ======================= Signature Level Mapping System =======================
    std::optional<UCHAR> GetSignatureLevel(UCHAR signerType) noexcept
    {
        // Map signer types to appropriate signature verification levels
        static const std::unordered_map<UCHAR, UCHAR> signerToSignatureLevel = {
            {static_cast<UCHAR>(PS_PROTECTED_SIGNER::None), 0x00},         // Unchecked
            {static_cast<UCHAR>(PS_PROTECTED_SIGNER::Authenticode), 0x04}, // Authenticode
            {static_cast<UCHAR>(PS_PROTECTED_SIGNER::CodeGen), 0x04},      // Authenticode level
            {static_cast<UCHAR>(PS_PROTECTED_SIGNER::Antimalware), 0x07},  // Antimalware vendor
            {static_cast<UCHAR>(PS_PROTECTED_SIGNER::Lsa), 0x0C},          // Windows component
            {static_cast<UCHAR>(PS_PROTECTED_SIGNER::Windows), 0x0C},      // Windows component
            {static_cast<UCHAR>(PS_PROTECTED_SIGNER::WinTcb), 0x0D},       // Windows TCB
            {static_cast<UCHAR>(PS_PROTECTED_SIGNER::WinSystem), 0x0E},    // Windows System
            {static_cast<UCHAR>(PS_PROTECTED_SIGNER::App), 0x0F}           // Application level
        };

        auto it = signerToSignatureLevel.find(signerType);
        return (it != signerToSignatureLevel.end()) ? std::make_optional(it->second) : std::nullopt;
    }

    std::optional<UCHAR> GetSectionSignatureLevel(UCHAR signerType) noexcept
    {
        // Section signature levels typically match main signature levels
        // for most signer types in the protection system
        return GetSignatureLevel(signerType);
    }

    // ======================= Process Dumpability Analysis System =======================
    ProcessDumpability CanDumpProcess(DWORD pid, const std::wstring& processName) noexcept
    {
        ProcessDumpability result;

        // Define system processes that are truly undumpable due to kernel-level protection
        static const std::unordered_set<DWORD> undumpablePids = {
            4,    // System process (NT kernel)
            188,  // Secure System (VSM/VBS protection)
            232,  // Registry process (kernel registry subsystem)
            3052  // Memory Compression (typical PID, kernel memory manager)
        };

        // Obfuscated process names to avoid static string detection
        static const std::unordered_set<std::wstring> undumpableNames = {
            OBFPROC(L"System"),
            OBFPROC(L"Secure System"), 
            OBFPROC(L"Registry"),
            OBFPROC(L"Memory Compression")
            // Note: Removed "[Unknown]" as it may be a dumpable process with unknown name
        };

        // Check against known undumpable process PIDs
        if (undumpablePids.find(pid) != undumpablePids.end())
        {
            result.CanDump = false;
            result.Reason = L"System kernel process - undumpable by design";
            return result;
        }

        // Check against known undumpable process names
        if (undumpableNames.find(processName) != undumpableNames.end())
        {
            result.CanDump = false;
            
            if (processName == OBFPROC(L"System"))
                result.Reason = L"Windows kernel process - cannot be dumped";
            else if (processName == OBFPROC(L"Secure System"))
                result.Reason = L"VSM/VBS protected process - virtualization-based security";
            else if (processName == OBFPROC(L"Registry"))
                result.Reason = L"Kernel registry subsystem - critical system component";
            else if (processName == OBFPROC(L"Memory Compression"))
                result.Reason = L"Kernel memory manager - system critical process";
            else
                result.Reason = L"System process - protected by Windows kernel";
            
            return result;
        }

        // CSRSS specific analysis (can be dumped with proper protection)
        auto csrssName = OBFPROC(L"csrss.exe");
        auto csrssShort = OBFPROC(L"csrss");
        if (processName == csrssName || processName == csrssShort) 
        {
            result.CanDump = true;
            result.Reason = L"CSRSS (Win32 subsystem) - dumpable with PPL-WinTcb or higher protection";
            return result;
        }

        // Warn about low PID processes (likely critical system processes)
        if (pid < 100 && pid != 0)
        {
            result.CanDump = true; // Might work with proper protection elevation
            result.Reason = L"Low PID system process - dumping may fail due to protection";
            return result;
        }

        // Enhanced analysis for unknown processes
        auto unknownProcess = OBFPROC(L"[Unknown]");
        if (processName == unknownProcess)
        {
            if (pid < 500) 
            {
                result.CanDump = true; // Often dumpable with elevated protection
                result.Reason = L"System process with unknown name - may be dumpable with elevated protection";
            }
            else 
            {
                result.CanDump = true;
                result.Reason = L"Process with unknown name - likely dumpable with appropriate privileges";
            }
            return result;
        }

        // Check for virtualization/hypervisor related processes
        auto vmmsPattern = OBFPROC(L"vmms");
        auto vmwpPattern = OBFPROC(L"vmwp");
        auto vmcomputePattern = OBFPROC(L"vmcompute");
        if (processName.find(vmmsPattern) != std::wstring::npos ||
            processName.find(vmwpPattern) != std::wstring::npos ||
            processName.find(vmcomputePattern) != std::wstring::npos)
        {
            result.CanDump = true;
            result.Reason = L"Hyper-V process - may require elevated protection to dump";
            return result;
        }

        // Check for Windows Defender and security software processes
        auto msMpEngPattern = OBFPROC(L"MsMpEng");
        auto nisSrvPattern = OBFPROC(L"NisSrv");
        auto secHealthPattern = OBFPROC(L"SecurityHealthService");
        if (processName.find(msMpEngPattern) != std::wstring::npos ||
            processName.find(nisSrvPattern) != std::wstring::npos ||
            processName.find(secHealthPattern) != std::wstring::npos)
        {
            result.CanDump = true;
            result.Reason = L"Security software - may require Antimalware protection level to dump";
            return result;
        }

        // Check for LSASS process (commonly targeted for credential analysis)
        auto lsassExe = OBFPROC(L"lsass.exe");
        auto lsassShort = OBFPROC(L"lsass");
        if (processName == lsassExe || processName == lsassShort)
        {
            result.CanDump = true;
            result.Reason = L"LSASS process - typically protected, may require PPL-WinTcb or higher";
            return result;
        }

        // Default case: most user-mode processes are dumpable with proper privileges
        result.CanDump = true;
        result.Reason = L"Standard user process - should be dumpable with appropriate privileges";
        return result;
    }
}