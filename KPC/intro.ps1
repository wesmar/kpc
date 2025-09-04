$introText = @"
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

"@

# Get all .cpp files in current directory
$cppFiles = Get-ChildItem -Path . -Filter "*.cpp"

# Count files with and without intro
$filesWithIntro = 0
$filesWithoutIntro = 0

foreach ($file in $cppFiles) {
    $content = Get-Content -Raw $file.FullName
    $introPattern = [regex]::Escape($introText.Trim())
    
    if ($content -match $introPattern) {
        $filesWithIntro++
    }
    else {
        $filesWithoutIntro++
    }
}

# Display summary
Write-Host "Found intro in $filesWithIntro files" -ForegroundColor Yellow
if ($filesWithIntro -gt 0) {
    $choice = Read-Host "Remove intro from all these files in batch? (Y/N)"
    if ($choice -eq 'Y' -or $choice -eq 'y') {
        foreach ($file in $cppFiles) {
            $content = Get-Content -Raw $file.FullName
            $introPattern = [regex]::Escape($introText.Trim())
            
            if ($content -match $introPattern) {
                $newContent = $content -replace $introPattern, ""
                $newContent = $newContent.TrimStart()
                Set-Content -Path $file.FullName -Value $newContent -NoNewline
                Write-Host "Removed intro from $($file.Name)" -ForegroundColor Green
            }
        }
    }
}

Write-Host "Intro not found in $filesWithoutIntro files" -ForegroundColor Yellow
if ($filesWithoutIntro -gt 0) {
    $choice = Read-Host "Add intro to all these files in batch? (Y/N)"
    if ($choice -eq 'Y' -or $choice -eq 'y') {
        foreach ($file in $cppFiles) {
            $content = Get-Content -Raw $file.FullName
            $introPattern = [regex]::Escape($introText.Trim())
            
            if (-not ($content -match $introPattern)) {
                $newContent = $introText + "`r`n" + $content
                Set-Content -Path $file.FullName -Value $newContent -NoNewline
                Write-Host "Added intro to $($file.Name)" -ForegroundColor Green
            }
        }
    }
}

Write-Host "Batch operation completed" -ForegroundColor Cyan
