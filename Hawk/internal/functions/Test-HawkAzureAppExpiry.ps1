function Test-HawkAzureAppExpiry {
    <#
    .SYNOPSIS
    Check if Azure App credentials are expired or expiring soon
    
    .DESCRIPTION
    Validates Azure App credential expiry dates and warns about upcoming expirations
    
    .PARAMETER AzureApp
    Azure App object from CSV import
    
    .PARAMETER WarningDays
    Days before expiry to show warning (default: 30)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSObject]$AzureApp,
        
        [Parameter(Mandatory = $false)]
        [int]$WarningDays = 30
    )
    
    $result = @{
        IsExpired = $false
        IsExpiringSoon = $false
        ExpiryDate = $null
        DaysUntilExpiry = 0
        Message = ""
    }
    
    try {
        $expiryDate = [DateTime]::Parse($AzureApp.Expiry)
        $result.ExpiryDate = $expiryDate
        
        $daysUntilExpiry = ($expiryDate - (Get-Date)).Days
        $result.DaysUntilExpiry = $daysUntilExpiry
        
        if ($expiryDate -lt (Get-Date)) {
            $result.IsExpired = $true
            $result.Message = "Credentials expired on $($AzureApp.Expiry)"
        } elseif ($daysUntilExpiry -le $WarningDays) {
            $result.IsExpiringSoon = $true
            $result.Message = "Credentials expire in $daysUntilExpiry days ($($AzureApp.Expiry))"
        } else {
            $result.Message = "Credentials expire on $($AzureApp.Expiry)"
        }
        
    } catch {
        $result.Message = "Could not parse expiry date: $($AzureApp.Expiry)"
    }
    
    return $result
}
