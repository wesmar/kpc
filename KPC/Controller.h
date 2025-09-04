#pragma once

#include "KpcDrv.h"
#include "OffsetFinder.h"
#include "TrustedInstallerIntegrator.h"
#include "Utils.h"
#include <vector>
#include <memory>
#include <optional>

// Structure representing a process entry in the kernel
struct ProcessEntry
{
    ULONG_PTR KernelAddress;        // Kernel memory address of EPROCESS structure
    DWORD Pid;                      // Process identifier
    UCHAR ProtectionLevel;          // Protection level (PP/PPL/None)
    UCHAR SignerType;               // Digital signature authority
    UCHAR SignatureLevel;           // Executable signature verification level
    UCHAR SectionSignatureLevel;    // DLL signature verification level
    std::wstring ProcessName;       // Process executable name
};

// Structure for process lookup results
struct ProcessMatch
{
    DWORD Pid = 0;                          // Process identifier (initialized to 0)
    std::wstring ProcessName;               // Process executable name
    ULONG_PTR KernelAddress = 0;            // Kernel memory address (initialized to 0)
};

class Controller
{
public:
    // ============================
    // Constructor & Destructor
    // ============================
    Controller();
    ~Controller();

    // Disable copy semantics, enable move semantics
    Controller(const Controller&) = delete;
    Controller& operator=(const Controller&) = delete;
    Controller(Controller&&) noexcept = default;
    Controller& operator=(Controller&&) noexcept = default;

    // ============================
    // Memory Dumping Operations (ATOMIC)
    // ============================
    bool DumpProcess(DWORD pid, const std::wstring& outputPath) noexcept;   // Create memory dump by PID
    bool DumpProcessByName(const std::wstring& processName, const std::wstring& outputPath) noexcept;

    // ============================
    // Process Information Operations (ATOMIC)
    // ============================
    bool ListProtectedProcesses() noexcept;                                 // Display all protected processes with color coding
    bool GetProcessProtection(DWORD pid) noexcept;                          // Query protection status by PID
    bool GetProcessProtectionByName(const std::wstring& processName) noexcept;

    // ============================
    // Process Protection Operations (ATOMIC)
    // ============================
    bool SetProcessProtection(DWORD pid, const std::wstring& protectionLevel, const std::wstring& signerType) noexcept;
    bool ProtectProcess(DWORD pid, const std::wstring& protectionLevel, const std::wstring& signerType) noexcept;
    bool UnprotectProcess(DWORD pid) noexcept;                              // Remove protection from process

    // Process operations by name (with pattern matching support) (ATOMIC)
    bool ProtectProcessByName(const std::wstring& processName, const std::wstring& protectionLevel, const std::wstring& signerType) noexcept;
    bool UnprotectProcessByName(const std::wstring& processName) noexcept;
    bool SetProcessProtectionByName(const std::wstring& processName, const std::wstring& protectionLevel, const std::wstring& signerType) noexcept;

    // Mass operations for batch processing (ATOMIC)
    bool UnprotectAllProcesses() noexcept;                                  // Remove protection from all protected processes
    bool UnprotectMultipleProcesses(const std::vector<std::wstring>& targets) noexcept; // Batch unprotection

    // ============================
    // Process Name Resolution (PUBLIC - used in main)
    // ============================
    std::optional<ProcessMatch> ResolveProcessName(const std::wstring& processName) noexcept;
    std::optional<ProcessMatch> ResolveNameWithoutDriver(const std::wstring& processName) noexcept;
    std::vector<ProcessMatch> FindProcessesByNameWithoutDriver(const std::wstring& pattern) noexcept;

    // ============================
    // Self-Protection Operations
    // ============================
    bool SelfProtect(const std::wstring& protectionLevel, const std::wstring& signerType) noexcept;

    // ============================
    // Emergency Cleanup (PUBLIC - used in signal handler)
    // ============================
    bool PerformAtomicCleanup() noexcept;  // MOVED from private section
    
    // ============================
    // System Integration & TrustedInstaller
    // ============================
    bool RunAsTrustedInstaller(const std::wstring& commandLine);
    bool AddToDefenderExclusions();
    bool AddContextMenuEntries();

    // ============================
    // Legacy Driver Management (Compatibility)
    // ============================
    bool InstallDriver() noexcept;                                          // Extract, decrypt and install driver from icon resource
    bool UninstallDriver() noexcept;                                        // Remove driver service and files
    bool StartDriverService() noexcept;                                     // Start kmpdc service
    bool StopDriverService() noexcept;                                      // Stop kmpdc service
    bool StartDriverServiceSilent() noexcept;                              // ADDED: Silent service start
    std::vector<BYTE> ExtractEncryptedDriver() noexcept;                    // Extract encrypted driver from icon (steganography)
    std::vector<BYTE> DecryptDriver(const std::vector<BYTE>& encryptedData) noexcept; // XOR decrypt with embedded key

private:
    // ============================
    // Core Components
    // ============================
    TrustedInstallerIntegrator m_trustedInstaller;                         // TrustedInstaller privilege escalation
    std::unique_ptr<KpcDrv> m_rtc;                                          // Kernel read/write interface
    std::unique_ptr<OffsetFinder> m_of;                                     // Kernel structure offset resolver

    // ============================
    // Atomic Driver Management
    // ============================
    bool EnsureCleanDriverOperation() noexcept;                            // cleanup → load → ready for atomic operation
    bool EnsureDriverAvailable() noexcept;                                 // Ensure driver is installed and running
    bool IsDriverCurrentlyLoaded() noexcept;                               // Check driver status
    
    // Atomic operation helpers
    bool PerformAtomicInit() noexcept;  
    bool PerformAtomicInitWithErrorCleanup() noexcept;

    // Helper method for unified process name resolution with driver management
    std::vector<ProcessMatch> FindProcessesByNameWithDriver(const std::wstring& pattern) noexcept;

    // ============================
    // Kernel Process Management (Low-Level)
    // ============================
    std::optional<ULONG_PTR> GetInitialSystemProcessAddress() noexcept;    // Get PsInitialSystemProcess address
    std::optional<ULONG_PTR> GetProcessKernelAddress(DWORD pid) noexcept;   // Get EPROCESS address by PID
    std::vector<ProcessEntry> GetProcessList() noexcept;                    // Enumerate all system processes
    std::optional<UCHAR> GetProcessProtection(ULONG_PTR addr) noexcept;     // Read protection from EPROCESS
    bool SetProcessProtection(ULONG_PTR addr, UCHAR protection) noexcept;   // Write protection to EPROCESS

    // ============================
    // Process Memory Operations
    // ============================
    bool CreateMiniDump(DWORD pid, const std::wstring& outputPath) noexcept; // Low-level dump creation
    bool SetCurrentProcessProtection(UCHAR protection) noexcept;            // Set protection on current process
    bool EnableDebugPrivilege() noexcept;                                   // Enable SeDebugPrivilege

    // ============================
    // Silent Driver Operations (Internal)
    // ============================
    bool InstallDriverSilently() noexcept;                                 // Silent driver installation
    bool RegisterDriverServiceSilent(const std::wstring& driverPath) noexcept; // Silent service registration
    bool RunAsTrustedInstallerSilent(const std::wstring& command);         // Silent TrustedInstaller execution

    // ============================
    // Process Name Pattern Matching
    // ============================
    std::vector<ProcessMatch> FindProcessesByName(const std::wstring& pattern) noexcept; // Find processes matching pattern
    bool IsPatternMatch(const std::wstring& processName, const std::wstring& pattern) noexcept; // Pattern matching logic
};
