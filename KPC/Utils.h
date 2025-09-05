#pragma once

#include "common.h"
#include <string>
#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace Utils
{
    // ======================= Helper Functions (moved from Controller.cpp) =======================
    std::optional<DWORD> ParsePid(const std::wstring& pidStr) noexcept;
    bool IsNumeric(const std::wstring& str) noexcept;
    std::vector<BYTE> ReadResource(int resourceId, const wchar_t* resourceType);
    bool WriteFile(const std::wstring& path, const std::vector<BYTE>& data);
    std::wstring ResolveUnknownProcessLocal(DWORD pid, ULONG_PTR kernelAddress, UCHAR protectionLevel, UCHAR signerType) noexcept;

    // ======================= Kernel Operations =======================
    std::optional<ULONG_PTR> GetKernelBaseAddress() noexcept;
    
    constexpr ULONG_PTR GetKernelAddress(ULONG_PTR base, DWORD offset) noexcept
    {
        return base + offset;
    }
    
    constexpr UCHAR GetProtectionLevel(UCHAR protection) noexcept
    {
        return protection & 0x07;
    }
    
    constexpr UCHAR GetSignerType(UCHAR protection) noexcept
    {
        return (protection & 0xf0) >> 4;
    }
    
    constexpr UCHAR GetProtection(UCHAR protectionLevel, UCHAR signerType) noexcept
    {
        return (signerType << 4) | protectionLevel;
    }
    
    // Extract lower 4 bits
    constexpr UCHAR GetSignatureLevelValue(UCHAR signatureLevel) noexcept
    {
        return signatureLevel & 0x0F; 
    }
    
    constexpr UCHAR GetSectionSignatureLevelValue(UCHAR sectionSignatureLevel) noexcept
    {
        return sectionSignatureLevel & 0x0F;
    }
    
    // ======================= String Conversion Functions =======================
    const wchar_t* GetProtectionLevelAsString(UCHAR protectionLevel) noexcept;
    const wchar_t* GetSignerTypeAsString(UCHAR signerType) noexcept;
    const wchar_t* GetSignatureLevelAsString(UCHAR signatureLevel) noexcept;
    
    // ======================= Parsing Functions =======================
    std::optional<UCHAR> GetProtectionLevelFromString(const std::wstring& protectionLevel) noexcept;
    std::optional<UCHAR> GetSignerTypeFromString(const std::wstring& signerType) noexcept;
    std::optional<UCHAR> GetSignatureLevel(UCHAR signerType) noexcept;
    std::optional<UCHAR> GetSectionSignatureLevel(UCHAR signerType) noexcept;
    
    // ======================= Process Operations =======================
    std::wstring GetProcessName(DWORD pid) noexcept;
    
    struct ProcessDumpability
    {
        bool CanDump;
        std::wstring Reason;
    };
    
    ProcessDumpability CanDumpProcess(DWORD pid, const std::wstring& processName) noexcept;
}