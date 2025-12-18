@{
    GUID = '4f9b1d2a-3c9e-4e6d-9c8a-EXAMPLE'
    ModuleVersion = '0.1.0'
    Author = 'exo-oauth2-smtp-tools'
    CompanyName = 'YourOrg'
    Copyright = '(c) 2025'
    Description = 'PowerShell module to provision and manage Exchange Online SMTP OAuth2 app identities (idempotent, secure, and automation-ready).'
    PowerShellVersion = '7.0'
    FunctionsToExport = @('New-ExoOauthSmtpAppIdentity','Get-ProtectedSecretFromFile','Get-ExoConfig')
    PrivateData = @{
        PSData = @{
            Tags = @('azure','exchange','oauth2','smtp','automation')
            LicenseUri = 'https://opensource.org/licenses/MIT'
        }
    }
}
