function Start-HawkInvestigationWithAzureApp {
    <#
    .SYNOPSIS
    Start Hawk investigation using Azure App authentication
    
    .DESCRIPTION
    Convenience wrapper that combines Azure App authentication with Hawk investigations
    
    .PARAMETER InvestigationType
    Type of investigation: Tenant or User
    
    .PARAMETER AzureAppCsvPath
    Path to CSV file with Azure App credentials
    
    .PARAMETER AzureAppClientName
    Name of Azure App client to use
    
    .PARAMETER UserPrincipalName
    UPN for user investigations
    
    .PARAMETER OutputPath
    Output directory for results
    
    .PARAMETER HeadlessMode
    Run without interactive prompts
    
    .EXAMPLE
    Start-HawkInvestigationWithAzureApp -InvestigationType "Tenant" -AzureAppCsvPath ".\creds.csv" -AzureAppClientName "SOC Client" -HeadlessMode
    
    .EXAMPLE
    Start-HawkInvestigationWithAzureApp -InvestigationType "User" -AzureAppCsvPath ".\creds.csv" -AzureAppClientName "SOC Client" -UserPrincipalName "user@domain.com" -HeadlessMode
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Tenant", "User")]
        [string]$InvestigationType,
        
        [Parameter(Mandatory = $true)]
        [string]$AzureAppCsvPath,
        
        [Parameter(Mandatory = $true)]
        [string]$AzureAppClientName,
        
        [Parameter(Mandatory = $false)]
        [string]$UserPrincipalName,
        
        [Parameter(Mandatory = $false)]
        [string]$OutputPath,
        
        [Parameter(Mandatory = $false)]
        [switch]$HeadlessMode
    )
    
    try {
        Write-Host "[HAWK] Starting $InvestigationType investigation with Azure App authentication" -ForegroundColor Cyan
        
        if ($InvestigationType -eq "User" -and [string]::IsNullOrEmpty($UserPrincipalName)) {
            throw "UserPrincipalName is required for user investigations"
        }
        
        $initParams = @{
            UseAzureApp = $true
            AzureAppCsvPath = $AzureAppCsvPath
            AzureAppClientName = $AzureAppClientName
            HeadlessMode = $HeadlessMode
        }
        
        if ($OutputPath) {
            $initParams.FilePath = $OutputPath
        }
        
        Initialize-HawkGlobalObject @initParams
        
        $status = Test-HawkAzureAppConnection
        if (-not $status.Connected) {
            throw "Azure App connection failed: $($status.ErrorMessage)"
        }
        
        switch ($InvestigationType) {
            "Tenant" {
                Write-Host "[HAWK] Starting tenant investigation..." -ForegroundColor Green
                Start-HawkTenantInvestigation
            }
            "User" {
                Write-Host "[HAWK] Starting user investigation for: $UserPrincipalName" -ForegroundColor Green
                Start-HawkUserInvestigation -UserPrincipalName $UserPrincipalName
            }
        }
        
        Write-Host "[HAWK] Investigation completed successfully" -ForegroundColor Green
        
        if ($Global:Hawk.FilePath) {
            Write-Host "[HAWK] Results saved to: $($Global:Hawk.FilePath)" -ForegroundColor Yellow
        }
        
    } catch {
        Write-Error "[HAWK] Investigation failed: $($_.Exception.Message)"
        throw
    }
}
