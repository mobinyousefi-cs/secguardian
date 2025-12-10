rule Suspicious_Executable_SectionNames
{
    meta:
        description = "Detects binaries with suspicious section names"
        author = "Mobin Yousefi"
        reference = "PoC"

    strings:
        $s1 = ".text"
        $s2 = ".rdata"
        $sus = ".upx"

    condition:
        uint16(0) == 0x5A4D and $sus
}

rule Generic_Encoded_PowerShell
{
    meta:
        description = "PowerShell with encodedcommand"
        author = "Mobin Yousefi"

    strings:
        $ps1 = "powershell"
        $enc = "-encodedcommand"

    condition:
        1 of ($ps*) and $enc
}
