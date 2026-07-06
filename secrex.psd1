@{
    RootModule        = 'secrex.psm1'
    ModuleVersion     = '0.2.0'
    GUID              = 'c7f4e1a2-8d3b-4e5f-9a6c-1b2d3e4f5a6b'
    Author            = 'Nik'
    Description       = 'Cross-platform per-user secret manager for PowerShell: Windows DPAPI, macOS Keychain (with a Touch ID vault), Linux AES key file. Project and personal scopes, .env import/export, interactive TUI.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('Invoke-Secrex')
    AliasesToExport   = @('secrex')
    CmdletsToExport   = @()
    VariablesToExport = @()
    PrivateData       = @{
        PSData = @{
            Tags       = @('secrets', 'security', 'keychain', 'dpapi', 'dotenv', 'cli', 'tui', 'macos', 'windows', 'linux')
            ProjectUri = 'https://github.com/nik-devs/secrex-cli'
            LicenseUri = 'https://github.com/nik-devs/secrex-cli/blob/main/LICENSE'
        }
    }
}
