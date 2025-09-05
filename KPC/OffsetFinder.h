#pragma once

#include "common.h"
#include <unordered_map>
#include <memory>
#include <optional>

enum class Offset
{
    KernelPsInitialSystemProcess,
    ProcessActiveProcessLinks,
    ProcessUniqueProcessId,
    ProcessProtection,
    ProcessSignatureLevel,
    ProcessSectionSignatureLevel
};

class OffsetFinder
{
public:
    OffsetFinder();
    ~OffsetFinder();
    
    OffsetFinder(const OffsetFinder&) = delete;
    OffsetFinder& operator=(const OffsetFinder&) = delete;
    OffsetFinder(OffsetFinder&&) noexcept = default;
    OffsetFinder& operator=(OffsetFinder&&) noexcept = default;

    std::optional<DWORD> GetOffset(Offset name) const noexcept;
    bool FindAllOffsets() noexcept;

private:
    struct ModuleDeleter
    {
        void operator()(HMODULE module) const noexcept
        {
            if (module) FreeLibrary(module);
        }
    };

    using ModuleHandle = std::unique_ptr<std::remove_pointer_t<HMODULE>, ModuleDeleter>;
    
    ModuleHandle m_kernelModule;
    std::unordered_map<Offset, DWORD> m_offsetMap;

    bool FindKernelPsInitialSystemProcessOffset() noexcept;
    bool FindProcessActiveProcessLinksOffset() noexcept;
    bool FindProcessUniqueProcessIdOffset() noexcept;
    bool FindProcessProtectionOffset() noexcept;
    bool FindProcessSignatureLevelOffset() noexcept;
    bool FindProcessSectionSignatureLevelOffset() noexcept;
};
