#pragma once

#include "common.h"
#include <memory>
#include <optional>

// kmpdc driver communication structures
// These structures must match the driver's expected format exactly
struct alignas(8) RTC_MEMORY_READ 
{
    BYTE Pad0[8];           // Padding for alignment
    DWORD64 Address;        // Target memory address to read
    BYTE Pad1[8];           // Additional padding
    DWORD Size;             // Number of bytes to read
    DWORD Value;            // Returned value from read operation
    BYTE Pad3[16];          // Final padding
};

struct alignas(8) RTC_MEMORY_WRITE 
{
    BYTE Pad0[8];           // Padding for alignment
    DWORD64 Address;        // Target memory address to write
    BYTE Pad1[8];           // Additional padding
    DWORD Size;             // Number of bytes to write
    DWORD Value;            // Value to write
    BYTE Pad3[16];          // Final padding
};

// KpcDrv class - Interface for kernel memory operations via kmpdc driver
class KpcDrv
{
public:
    // ============================
    // Constructor & Destructor
    // ============================
    KpcDrv();
    ~KpcDrv();

    // Disable copy semantics, enable move semantics
    KpcDrv(const KpcDrv&) = delete;
    KpcDrv& operator=(const KpcDrv&) = delete;
    KpcDrv(KpcDrv&&) noexcept = default;
    KpcDrv& operator=(KpcDrv&&) noexcept = default;

    // ============================
    // Driver Connection Management
    // ============================
    bool Initialize() noexcept;                                 // Initialize driver connection
    void Cleanup() noexcept;                                    // Force cleanup handle for atomic operations
    bool IsConnected() const noexcept;                          // Check if driver is connected

    // ============================
    // Memory Read Operations
    // ============================
    std::optional<BYTE> Read8(ULONG_PTR address) noexcept;      // Read 8-bit value
    std::optional<WORD> Read16(ULONG_PTR address) noexcept;     // Read 16-bit value
    std::optional<DWORD> Read32(ULONG_PTR address) noexcept;    // Read 32-bit value
    std::optional<DWORD64> Read64(ULONG_PTR address) noexcept;  // Read 64-bit value
    std::optional<ULONG_PTR> ReadPtr(ULONG_PTR address) noexcept; // Read pointer (platform-dependent size)
    
    // ============================
    // Memory Write Operations
    // ============================
    bool Write8(ULONG_PTR address, BYTE value) noexcept;        // Write 8-bit value
    bool Write16(ULONG_PTR address, WORD value) noexcept;       // Write 16-bit value
    bool Write32(ULONG_PTR address, DWORD value) noexcept;      // Write 32-bit value
    bool Write64(ULONG_PTR address, DWORD64 value) noexcept;    // Write 64-bit value

private:
    // Smart handle wrapper for automatic cleanup
    struct HandleDeleter
    {
        void operator()(HANDLE handle) const noexcept
        {
            if (handle && handle != INVALID_HANDLE_VALUE)
                CloseHandle(handle);
        }
    };

    using UniqueHandle = std::unique_ptr<std::remove_pointer_t<HANDLE>, HandleDeleter>;
    
    // ============================
    // Private Members
    // ============================
    std::wstring m_deviceName;      // Driver device name (\\.\kmpdc)
    UniqueHandle m_deviceHandle;    // Handle to driver device

    // ============================
    // Low-Level Communication
    // ============================
    std::optional<DWORD> Read(ULONG_PTR address, DWORD valueSize) noexcept;    // Generic read operation
    bool Write(ULONG_PTR address, DWORD valueSize, DWORD value) noexcept;      // Generic write operation
};
