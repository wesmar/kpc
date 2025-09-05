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
#include <charconv>
#include <fstream>
#include <vector>
#include <filesystem>
#include "resource.h"

namespace fs = std::filesystem;

#pragma comment(lib, "psapi.lib")

namespace Utils
{
    std::optional<DWORD> ParsePid(const std::wstring& pidStr) noexcept {
        if (pidStr.empty()) return std::nullopt;

        std::string narrowStr;
        narrowStr.reserve(pidStr.size());
        for (wchar_t wc : pidStr) {
            if (wc > 127) return std::nullopt;
            narrowStr.push_back(static_cast<char>(wc));
        }

        DWORD result = 0;
        auto [ptr, ec] = std::from_chars(narrowStr.data(), narrowStr.data() + narrowStr.size(), result);
        return (ec == std::errc{} && ptr == narrowStr.data() + narrowStr.size()) ? std::make_optional(result) : std::nullopt;
    }

    bool IsNumeric(const std::wstring& str) noexcept {
        if (str.empty()) return false;
        for (wchar_t ch : str) {
            if (ch < L'0' || ch > L'9') return false;
        }
        return true;
    }

    std::vector<BYTE> ReadResource(int resourceId, const wchar_t* resourceType) {
        HRSRC hRes = FindResource(nullptr, MAKEINTRESOURCE(resourceId), resourceType);
        if (!hRes) return {};
        
        HGLOBAL hData = LoadResource(nullptr, hRes);
        if (!hData) return {};
        
        DWORD dataSize = SizeofResource(nullptr, hRes);
        void* pData = LockResource(hData);
        
        return std::vector<BYTE>(static_cast<BYTE*>(pData), static_cast<BYTE*>(pData) + dataSize);
    }

    bool WriteFile(const std::wstring& path, const std::vector<BYTE>& data) {
        HANDLE hFile = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) return false;
        
        DWORD bytesWritten;
        BOOL success = ::WriteFile(hFile, data.data(), static_cast<DWORD>(data.size()), &bytesWritten, nullptr);
        CloseHandle(hFile);
        
        return success && bytesWritten == data.size();
    }

    std::wstring ResolveUnknownProcessLocal(DWORD pid, ULONG_PTR kernelAddress, UCHAR protectionLevel, UCHAR signerType) noexcept {
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
        if (hProcess) {
            wchar_t imageName[MAX_PATH] = {0};
            if (GetProcessImageFileNameW(hProcess, imageName, MAX_PATH)) {
                std::wstring fullPath(imageName);
                size_t lastSlash = fullPath.find_last_of(L'\\');
                if (lastSlash != std::wstring::npos) {
                    CloseHandle(hProcess);
                    return fullPath.substr(lastSlash + 1);
                }
            }

            DWORD size = MAX_PATH;
            wchar_t processPath[MAX_PATH] = {0};
            if (QueryFullProcessImageNameW(hProcess, 0, processPath, &size)) {
                std::wstring fullPath(processPath);
                size_t lastSlash = fullPath.find_last_of(L'\\');
                if (lastSlash != std::wstring::npos) {
                    CloseHandle(hProcess);
                    return fullPath.substr(lastSlash + 1);
                }
            }
            CloseHandle(hProcess);
        }

        // Method 2: Process snapshot enumeration
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

        // Method 3: Protection-based classification system
        PS_PROTECTED_TYPE protection = static_cast<PS_PROTECTED_TYPE>(protectionLevel);
        PS_PROTECTED_SIGNER signer = static_cast<PS_PROTECTED_SIGNER>(signerType);
        
        if (protection == PS_PROTECTED_TYPE::Protected && signer == PS_PROTECTED_SIGNER::WinSystem) {
            return (pid < 300) ? OBFPROC(L"Kernel System Process") : OBFPROC(L"Protected System Service");
        }
        
        if (protection == PS_PROTECTED_TYPE::ProtectedLight && signer == PS_PROTECTED_SIGNER::WinTcb) {
            return (pid < 500) ? OBFPROC(L"Core System Service") : OBFPROC(L"Trusted System Service");
        }
        
        if (protection == PS_PROTECTED_TYPE::Protected && signer == PS_PROTECTED_SIGNER::Windows) {
            return OBFPROC(L"Windows System Component");
        }
        
        if (protection == PS_PROTECTED_TYPE::ProtectedLight && signer == PS_PROTECTED_SIGNER::Windows) {
            return OBFPROC(L"Windows Service");
        }

        if (pid >= 8 && pid <= 96 && pid % 4 == 0) {
            return OBFPROC(L"Kernel Worker");
        }
        
        if (pid >= 100 && pid <= 300) {
            return OBFPROC(L"Early System Process");
        }

        return OBFPROC(L"Process_") + std::to_wstring(pid);
    }

    std::optional<ULONG_PTR> GetKernelBaseAddress() noexcept
    {
        LPVOID drivers[1024];
        DWORD cbNeeded;
        
        if (!EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded))
            return std::nullopt;

        return reinterpret_cast<ULONG_PTR>(drivers[0]);
    }

    std::wstring GetProcessName(DWORD pid) noexcept
    {
        if (pid == 0)
            return OBFPROC(L"System Idle Process");
        if (pid == 4)
            return OBFPROC(L"System [NT Kernel Core]");

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

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!hProcess) {
            hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        }
        
        if (hProcess) {
            wchar_t processName[MAX_PATH] = {0};
            DWORD size = MAX_PATH;
            
            if (QueryFullProcessImageNameW(hProcess, 0, processName, &size)) {
                std::wstring fullPath(processName);
                size_t lastSlash = fullPath.find_last_of(L'\\');
                if (lastSlash != std::wstring::npos) {
                    CloseHandle(hProcess);
                    return fullPath.substr(lastSlash + 1);
                }
            }

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

        return OBFPROC(L"[Unknown]");
    }

    const wchar_t* GetProtectionLevelAsString(UCHAR protectionLevel) noexcept
    {
        // Statyczny cache - stringi będą żyły przez cały czas życia programu
        static const std::wstring none = OBFPATH(L"None");
        static const std::wstring ppl = OBFPATH(L"PPL");
        static const std::wstring pp = OBFPATH(L"PP");
        static const std::wstring unknown = OBFPATH(L"Unknown");

        switch (static_cast<PS_PROTECTED_TYPE>(protectionLevel))
        {
            case PS_PROTECTED_TYPE::None:           return none.c_str();
            case PS_PROTECTED_TYPE::ProtectedLight: return ppl.c_str();
            case PS_PROTECTED_TYPE::Protected:      return pp.c_str();
            default:                                return unknown.c_str();
        }
    }

    const wchar_t* GetSignerTypeAsString(UCHAR signerType) noexcept
    {
        // Statyczny cache - stringi będą żyły przez cały czas życia programu
        static const std::wstring none = OBFPATH(L"None");
        static const std::wstring authenticode = OBFPATH(L"Authenticode");
        static const std::wstring codegen = OBFPATH(L"CodeGen");
        static const std::wstring antimalware = OBFPATH(L"Antimalware");
        static const std::wstring lsa = OBFPATH(L"Lsa");
        static const std::wstring windows = OBFPATH(L"Windows");
        static const std::wstring wintcb = OBFPATH(L"WinTcb");
        static const std::wstring winsystem = OBFPATH(L"WinSystem");
        static const std::wstring app = OBFPATH(L"App");
        static const std::wstring unknown = OBFPATH(L"Unknown");

        switch (static_cast<PS_PROTECTED_SIGNER>(signerType))
        {
            case PS_PROTECTED_SIGNER::None:         return none.c_str();
            case PS_PROTECTED_SIGNER::Authenticode: return authenticode.c_str();
            case PS_PROTECTED_SIGNER::CodeGen:      return codegen.c_str();
            case PS_PROTECTED_SIGNER::Antimalware:  return antimalware.c_str();
            case PS_PROTECTED_SIGNER::Lsa:          return lsa.c_str();
            case PS_PROTECTED_SIGNER::Windows:      return windows.c_str();
            case PS_PROTECTED_SIGNER::WinTcb:       return wintcb.c_str();
            case PS_PROTECTED_SIGNER::WinSystem:    return winsystem.c_str();
            case PS_PROTECTED_SIGNER::App:          return app.c_str();
            default:                                return unknown.c_str();
        }
    }

    const wchar_t* GetSignatureLevelAsString(UCHAR signatureLevel) noexcept
    {
        // Statyczny cache dla wszystkich poziomów podpisów
        static const auto initSignatureLevels = []() {
            std::unordered_map<UCHAR, std::wstring> levels;
            levels[0x00] = OBFPATH(L"Unchecked");       levels[0x01] = OBFPATH(L"Unsigned");         levels[0x02] = OBFPATH(L"Enterprise");
            levels[0x03] = OBFPATH(L"Custom1");         levels[0x04] = OBFPATH(L"Authenticode");     levels[0x05] = OBFPATH(L"Custom2");
            levels[0x06] = OBFPATH(L"Store");           levels[0x07] = OBFPATH(L"Antimalware");      levels[0x08] = OBFPATH(L"Microsoft");
            levels[0x09] = OBFPATH(L"Custom4");         levels[0x0A] = OBFPATH(L"Custom5");          levels[0x0B] = OBFPATH(L"Dynamic");
            levels[0x0C] = OBFPATH(L"Windows");         levels[0x0D] = OBFPATH(L"WinTcb");           levels[0x0E] = OBFPATH(L"WinSystem");
            levels[0x0F] = OBFPATH(L"App");             levels[0x10] = OBFPATH(L"Custom6");          levels[0x11] = OBFPATH(L"Custom7");
            levels[0x12] = OBFPATH(L"Custom8");         levels[0x13] = OBFPATH(L"Custom9");          levels[0x14] = OBFPATH(L"Custom10");
            levels[0x15] = OBFPATH(L"DevUnlock");       levels[0x16] = OBFPATH(L"Custom11");         levels[0x17] = OBFPATH(L"Custom12");
            levels[0x18] = OBFPATH(L"Custom13");        levels[0x19] = OBFPATH(L"Custom14");         levels[0x1A] = OBFPATH(L"Custom15");
            levels[0x1B] = OBFPATH(L"StoreApp");        levels[0x1C] = OBFPATH(L"WSL");              levels[0x1D] = OBFPATH(L"None2");
            levels[0x1E] = OBFPATH(L"WinTcb2");         levels[0x1F] = OBFPATH(L"WinSystemHigh");    levels[0x20] = OBFPATH(L"PplLight");
            levels[0x21] = OBFPATH(L"PplMedium");       levels[0x22] = OBFPATH(L"PplHigh");          levels[0x30] = OBFPATH(L"SystemLight");
            levels[0x31] = OBFPATH(L"SystemMedium");    levels[0x32] = OBFPATH(L"SystemHigh");       levels[0x33] = OBFPATH(L"SystemCritical");
            levels[0x34] = OBFPATH(L"KernelLight");     levels[0x35] = OBFPATH(L"KernelMedium");     levels[0x36] = OBFPATH(L"KernelHigh");
            levels[0x37] = OBFPATH(L"KernelCritical");  levels[0x38] = OBFPATH(L"HypervisorLight"); levels[0x39] = OBFPATH(L"HypervisorMedium");
            levels[0x3A] = OBFPATH(L"HypervisorHigh");  levels[0x3B] = OBFPATH(L"HypervisorCritical"); levels[0x3C] = OBFPATH(L"VbsLight");
            levels[0x3D] = OBFPATH(L"VbsMedium");       levels[0x3E] = OBFPATH(L"VbsHigh");          levels[0x3F] = OBFPATH(L"VbsCritical");
            return levels;
        };

        static const auto signatureLevels = initSignatureLevels();
        static const std::wstring reserved = OBFPATH(L"Reserved");

        auto it = signatureLevels.find(signatureLevel);
        return (it != signatureLevels.end()) ? it->second.c_str() : reserved.c_str();
    }

    std::optional<UCHAR> GetProtectionLevelFromString(const std::wstring& protectionLevel) noexcept
    {
        static const std::unordered_map<std::wstring, UCHAR> levels = {
            {OBFPATH(L"none"), static_cast<UCHAR>(PS_PROTECTED_TYPE::None)},
            {OBFPATH(L"ppl"), static_cast<UCHAR>(PS_PROTECTED_TYPE::ProtectedLight)},
            {OBFPATH(L"pp"), static_cast<UCHAR>(PS_PROTECTED_TYPE::Protected)}
        };

        std::wstring lower = protectionLevel;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);

        auto it = levels.find(lower);
        return (it != levels.end()) ? std::make_optional(it->second) : std::nullopt;
    }

    std::optional<UCHAR> GetSignerTypeFromString(const std::wstring& signerType) noexcept
    {
        std::wstring lower = signerType;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);

        if (lower == L"none") return static_cast<UCHAR>(PS_PROTECTED_SIGNER::None);
        if (lower == L"authenticode") return static_cast<UCHAR>(PS_PROTECTED_SIGNER::Authenticode);
        if (lower == L"codegen") return static_cast<UCHAR>(PS_PROTECTED_SIGNER::CodeGen);
        if (lower == L"antimalware") return static_cast<UCHAR>(PS_PROTECTED_SIGNER::Antimalware);
        if (lower == L"lsa") return static_cast<UCHAR>(PS_PROTECTED_SIGNER::Lsa);
        if (lower == L"windows") return static_cast<UCHAR>(PS_PROTECTED_SIGNER::Windows);
        if (lower == L"wintcb") return static_cast<UCHAR>(PS_PROTECTED_SIGNER::WinTcb);
        if (lower == L"winsystem") return static_cast<UCHAR>(PS_PROTECTED_SIGNER::WinSystem);
        if (lower == L"app") return static_cast<UCHAR>(PS_PROTECTED_SIGNER::App);
        
        return std::nullopt;
    }

    std::optional<UCHAR> GetSignatureLevel(UCHAR signerType) noexcept
    {
        static const std::unordered_map<UCHAR, UCHAR> signerToSignatureLevel = {
            {static_cast<UCHAR>(PS_PROTECTED_SIGNER::None), 0x00},
            {static_cast<UCHAR>(PS_PROTECTED_SIGNER::Authenticode), 0x04},
            {static_cast<UCHAR>(PS_PROTECTED_SIGNER::CodeGen), 0x04},
            {static_cast<UCHAR>(PS_PROTECTED_SIGNER::Antimalware), 0x07},
            {static_cast<UCHAR>(PS_PROTECTED_SIGNER::Lsa), 0x0C},
            {static_cast<UCHAR>(PS_PROTECTED_SIGNER::Windows), 0x0C},
            {static_cast<UCHAR>(PS_PROTECTED_SIGNER::WinTcb), 0x0D},
            {static_cast<UCHAR>(PS_PROTECTED_SIGNER::WinSystem), 0x0E},
            {static_cast<UCHAR>(PS_PROTECTED_SIGNER::App), 0x0F}
        };

        auto it = signerToSignatureLevel.find(signerType);
        return (it != signerToSignatureLevel.end()) ? std::make_optional(it->second) : std::nullopt;
    }

    std::optional<UCHAR> GetSectionSignatureLevel(UCHAR signerType) noexcept
    {
        return GetSignatureLevel(signerType);
    }

    ProcessDumpability CanDumpProcess(DWORD pid, const std::wstring& processName) noexcept
    {
        ProcessDumpability result;

        static const std::unordered_set<DWORD> undumpablePids = {
            4,    // System process
            188,  // Secure System
            232,  // Registry process
            3052  // Memory Compression
        };

        static const std::unordered_set<std::wstring> undumpableNames = {
            OBFPROC(L"System"),
            OBFPROC(L"Secure System"), 
            OBFPROC(L"Registry"),
            OBFPROC(L"Memory Compression")
        };

        if (undumpablePids.find(pid) != undumpablePids.end())
        {
            result.CanDump = false;
            result.Reason = OBFERR(L"System kernel process - undumpable by design");
            return result;
        }

        if (undumpableNames.find(processName) != undumpableNames.end())
        {
            result.CanDump = false;
            
            auto systemProcess = OBFPROC(L"System");
            auto secureSystemProcess = OBFPROC(L"Secure System");
            auto registryProcess = OBFPROC(L"Registry");
            auto memoryCompressionProcess = OBFPROC(L"Memory Compression");
            
            if (processName == systemProcess)
                result.Reason = OBFERR(L"Windows kernel process - cannot be dumped");
            else if (processName == secureSystemProcess)
                result.Reason = OBFERR(L"VSM/VBS protected process - virtualization-based security");
            else if (processName == registryProcess)
                result.Reason = OBFERR(L"Kernel registry subsystem - critical system component");
            else if (processName == memoryCompressionProcess)
                result.Reason = OBFERR(L"Kernel memory manager - system critical process");
            else
                result.Reason = OBFERR(L"System process - protected by Windows kernel");
            
            return result;
        }

        auto csrssName = OBFPROC(L"csrss.exe");
        auto csrssShort = OBFPROC(L"csrss");
        if (processName == csrssName || processName == csrssShort) 
        {
            result.CanDump = true;
            result.Reason = OBFINFO(L"CSRSS (Win32 subsystem) - dumpable with PPL-WinTcb or higher protection");
            return result;
        }

        if (pid < 100 && pid != 0)
        {
            result.CanDump = true;
            result.Reason = OBFINFO(L"Low PID system process - dumping may fail due to protection");
            return result;
        }

        auto unknownProcess = OBFPROC(L"[Unknown]");
        if (processName == unknownProcess)
        {
            if (pid < 500) 
            {
                result.CanDump = true;
                result.Reason = OBFINFO(L"System process with unknown name - may be dumpable with elevated protection");
            }
            else 
            {
                result.CanDump = true;
                result.Reason = OBFINFO(L"Process with unknown name - likely dumpable with appropriate privileges");
            }
            return result;
        }

        auto vmmsPattern = OBFPROC(L"vmms");
        auto vmwpPattern = OBFPROC(L"vmwp");
        auto vmcomputePattern = OBFPROC(L"vmcompute");
        if (processName.find(vmmsPattern) != std::wstring::npos ||
            processName.find(vmwpPattern) != std::wstring::npos ||
            processName.find(vmcomputePattern) != std::wstring::npos)
        {
            result.CanDump = true;
            result.Reason = OBFINFO(L"Hyper-V process - may require elevated protection to dump");
            return result;
        }

        auto msMpEngPattern = OBFPROC(L"MsMpEng");
        auto nisSrvPattern = OBFPROC(L"NisSrv");
        auto secHealthPattern = OBFPROC(L"SecurityHealthService");
        if (processName.find(msMpEngPattern) != std::wstring::npos ||
            processName.find(nisSrvPattern) != std::wstring::npos ||
            processName.find(secHealthPattern) != std::wstring::npos)
        {
            result.CanDump = true;
            result.Reason = OBFINFO(L"Security software - may require Antimalware protection level to dump");
            return result;
        }

        auto lsassExe = OBFPROC(L"lsass.exe");
        auto lsassShort = OBFPROC(L"lsass");
        if (processName == lsassExe || processName == lsassShort)
        {
            result.CanDump = true;
            result.Reason = OBFINFO(L"LSASS process - typically protected, may require PPL-WinTcb or higher");
            return result;
        }

        result.CanDump = true;
        result.Reason = OBFINFO(L"Standard user process - should be dumpable with appropriate privileges");
        return result;
    }
}