#pragma once

#include "common.h"
#include <string>
#include <optional>
#include <unordered_map>
#include <unordered_set>

namespace Utils
{
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
    
    // Removed Polish comment - Extract lower 4 bits
    constexpr UCHAR GetSignatureLevelValue(UCHAR signatureLevel) noexcept
    {
        return signatureLevel & 0x0F; 
    }
    
    constexpr UCHAR GetSectionSignatureLevelValue(UCHAR sectionSignatureLevel) noexcept
    {
        return sectionSignatureLevel & 0x0F;
    }
    
    const wchar_t* GetProtectionLevelAsString(UCHAR protectionLevel) noexcept;
    const wchar_t* GetSignerTypeAsString(UCHAR signerType) noexcept;
    const wchar_t* GetSignatureLevelAsString(UCHAR signatureLevel) noexcept;
    
    std::optional<UCHAR> GetProtectionLevelFromString(const std::wstring& protectionLevel) noexcept;
    std::optional<UCHAR> GetSignerTypeFromString(const std::wstring& signerType) noexcept;
    std::optional<UCHAR> GetSignatureLevel(UCHAR signerType) noexcept;
    std::optional<UCHAR> GetSectionSignatureLevel(UCHAR signerType) noexcept;
    
    std::wstring GetProcessName(DWORD pid) noexcept;
    
    struct ProcessDumpability
    {
        bool CanDump;
        std::wstring Reason;
    };
    
    ProcessDumpability CanDumpProcess(DWORD pid, const std::wstring& processName) noexcept;
}
