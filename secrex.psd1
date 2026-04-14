@{
    RootModule        = 'secrex.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = 'c7f4e1a2-8d3b-4e5f-9a6c-1b2d3e4f5a6b'
    Author            = 'Nik'
    Description       = 'Per-user secret manager for PowerShell, DPAPI-encrypted, with project and personal scopes.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('Invoke-Secrex')
    AliasesToExport   = @('secrex')
    CmdletsToExport   = @()
    VariablesToExport = @()
}
