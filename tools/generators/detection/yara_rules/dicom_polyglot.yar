/*
 * YARA Rules for DICOM Polyglot Detection
 *
 * These rules detect executable content hidden in DICOM preambles,
 * as described in CVE-2019-11687.
 *
 * Usage:
 *   yara detection.yara /path/to/scan
 *
 * References:
 *   - https://github.com/d00rt/pedicom
 *   - https://www.praetorian.com/blog/elfdicom-poc-malware-polyglot-exploiting-linux-based-medical-devices/
 */

rule DICOM_PE_Polyglot
{
    meta:
        description = "Detects Windows PE executable hidden in DICOM preamble"
        author = "dicom-fuzzer"
        cve = "CVE-2019-11687"
        severity = "high"
        reference = "https://researchcylera.wpcomstaging.com/2019/04/16/pe-dicom-medical-malware/"

    strings:
        $mz_header = { 4D 5A }              // MZ DOS header magic
        $dicm_magic = { 44 49 43 4D }       // DICM magic at offset 128
        $pe_sig = "PE\x00\x00"              // PE signature

    condition:
        $mz_header at 0 and
        $dicm_magic at 128 and
        $pe_sig in (0..500)
}

rule DICOM_PE_Polyglot_Relaxed
{
    meta:
        description = "Detects potential PE/DICOM polyglot (relaxed matching)"
        author = "dicom-fuzzer"
        cve = "CVE-2019-11687"
        severity = "medium"

    strings:
        $mz_header = { 4D 5A }              // MZ DOS header magic
        $dicm_magic = { 44 49 43 4D }       // DICM magic

    condition:
        $mz_header at 0 and
        $dicm_magic at 128
}

rule DICOM_ELF_Polyglot
{
    meta:
        description = "Detects Linux ELF executable hidden in DICOM preamble"
        author = "dicom-fuzzer"
        cve = "CVE-2019-11687"
        severity = "high"
        reference = "https://www.praetorian.com/blog/elfdicom-poc-malware-polyglot-exploiting-linux-based-medical-devices/"

    strings:
        $elf_magic = { 7F 45 4C 46 }        // ELF magic (\x7fELF)
        $dicm_magic = { 44 49 43 4D }       // DICM magic at offset 128

    condition:
        $elf_magic at 0 and
        $dicm_magic at 128
}

rule DICOM_ELF32_Polyglot
{
    meta:
        description = "Detects 32-bit ELF executable in DICOM preamble"
        author = "dicom-fuzzer"
        cve = "CVE-2019-11687"
        severity = "high"

    strings:
        $elf_magic = { 7F 45 4C 46 01 }     // ELF magic + 32-bit class
        $dicm_magic = { 44 49 43 4D }       // DICM magic

    condition:
        $elf_magic at 0 and
        $dicm_magic at 128
}

rule DICOM_ELF64_Polyglot
{
    meta:
        description = "Detects 64-bit ELF executable in DICOM preamble"
        author = "dicom-fuzzer"
        cve = "CVE-2019-11687"
        severity = "high"

    strings:
        $elf_magic = { 7F 45 4C 46 02 }     // ELF magic + 64-bit class
        $dicm_magic = { 44 49 43 4D }       // DICM magic

    condition:
        $elf_magic at 0 and
        $dicm_magic at 128
}

rule DICOM_MachO_Polyglot
{
    meta:
        description = "Detects macOS Mach-O executable in DICOM preamble"
        author = "dicom-fuzzer"
        cve = "CVE-2019-11687"
        severity = "high"

    strings:
        $macho_32 = { FE ED FA CE }         // Mach-O 32-bit
        $macho_64 = { FE ED FA CF }         // Mach-O 64-bit
        $macho_32_rev = { CE FA ED FE }     // Mach-O 32-bit (reversed)
        $macho_64_rev = { CF FA ED FE }     // Mach-O 64-bit (reversed)
        $dicm_magic = { 44 49 43 4D }       // DICM magic

    condition:
        ($macho_32 at 0 or $macho_64 at 0 or $macho_32_rev at 0 or $macho_64_rev at 0) and
        $dicm_magic at 128
}

rule DICOM_Suspicious_Preamble
{
    meta:
        description = "Detects suspicious content in DICOM preamble (generic)"
        author = "dicom-fuzzer"
        severity = "low"

    strings:
        $dicm_magic = { 44 49 43 4D }       // DICM magic

        // Suspicious strings that shouldn't be in medical images
        $cmd = "cmd.exe" nocase
        $powershell = "powershell" nocase
        $bash = "/bin/bash"
        $sh = "/bin/sh"
        $wget = "wget "
        $curl = "curl "
        $http = "http://"
        $https = "https://"

    condition:
        $dicm_magic at 128 and
        any of ($cmd, $powershell, $bash, $sh, $wget, $curl, $http, $https) in (0..127)
}

rule DICOM_Shellcode_Indicators
{
    meta:
        description = "Detects potential shellcode patterns in DICOM preamble"
        author = "dicom-fuzzer"
        severity = "medium"

    strings:
        $dicm_magic = { 44 49 43 4D }       // DICM magic

        // Common shellcode patterns
        $int80 = { CD 80 }                  // Linux syscall
        $syscall = { 0F 05 }                // Linux 64-bit syscall
        $sysenter = { 0F 34 }               // Windows sysenter
        $nop_sled = { 90 90 90 90 90 }      // NOP sled

    condition:
        $dicm_magic at 128 and
        any of ($int80, $syscall, $sysenter, $nop_sled) in (0..127)
}

rule DICOM_Clean_Preamble
{
    meta:
        description = "Identifies DICOM files with safe null-byte preamble"
        author = "dicom-fuzzer"
        severity = "info"

    strings:
        $null_preamble = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $dicm_magic = { 44 49 43 4D }

    condition:
        $null_preamble at 0 and
        $dicm_magic at 128
}

rule DICOM_TIFF_Preamble
{
    meta:
        description = "Identifies DICOM files with TIFF-compatible preamble"
        author = "dicom-fuzzer"
        severity = "info"

    strings:
        $tiff_le = { 49 49 2A 00 }          // TIFF little-endian
        $tiff_be = { 4D 4D 00 2A }          // TIFF big-endian
        $dicm_magic = { 44 49 43 4D }

    condition:
        ($tiff_le at 0 or $tiff_be at 0) and
        $dicm_magic at 128
}
