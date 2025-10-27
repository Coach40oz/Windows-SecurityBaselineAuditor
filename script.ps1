<#
.SYNOPSIS
    Security Baseline Auditor - Compare system security settings against best practices

.DESCRIPTION
    This script performs security compliance checks against industry standard benchmarks
    for Windows Server and Workstation environments. It inspects local security policy,
    registry settings, services, and configurations to identify security gaps.
    
    Inspired by CIS, NIST, and Microsoft Security baselines, but simplified for easy implementation.

.NOTES
    Version: 1.0
    Compatible with: Windows Server 2016+, Windows 10/11
#>

# Configuration
$LogPath = "C:\Logs\SecurityAudit"
$LogFile = Join-Path -Path $LogPath -ChildPath "SecurityAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$ExportCSV = $true
$CSVPath = Join-Path -Path $LogPath -ChildPath "SecurityAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
$CheckServerOnly = $false # Set to $true to skip workstation-specific checks
$IncludeAllResults = $false # Set to $true to include passing checks in the report

# Create log directory if it doesn't exist
if (!(Test-Path -Path $LogPath)) {
    try {
        New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
        Write-Host "Created log directory: $LogPath" -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to create log directory: $_" -ForegroundColor Red
        exit 1
    }
}

# Initialize results collection
$Results = @{
    ComputerInfo = @{
        ComputerName = $env:COMPUTERNAME
        OSVersion = ""
        LastBootTime = $null
        IsServer = $false
        Domain = $env:USERDOMAIN
        IPAddresses = @()
        ScanTime = Get-Date
    }
    AccountPolicies = @()
    LocalPolicies = @()
    AuditPolicies = @()
    RegistrySettings = @()
    ServicesCheck = @()
    NetworkSettings = @()
    AdvancedSettings = @()
    Summary = @{
        TotalChecks = 0
        PassedChecks = 0
        FailedChecks = 0
        WarningChecks = 0
        ComplianceScore = 0
    }
}

# Function to write logs
function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    try {
        Add-Content -Path $LogFile -Value $logEntry -ErrorAction Stop
        
        # Also output to console with color coding
        switch ($Level) {
            "Error" { Write-Host $logEntry -ForegroundColor Red }
            "Warning" { Write-Host $logEntry -ForegroundColor Yellow }
            "Success" { Write-Host $logEntry -ForegroundColor Green }
            default { Write-Host $logEntry }
        }
    }
    catch {
        Write-Host "Failed to write to log file: $_" -ForegroundColor Red
    }
}

# Function to add a check result
function Add-CheckResult {
    param (
        [string]$Category,
        [string]$CheckName,
        [string]$Description,
        [string]$Result,
        [string]$ExpectedValue,
        [string]$ActualValue,
        [string]$Severity = "Medium", # High, Medium, Low
        [string]$Recommendation,
        [string]$Reference = ""
    )
    
    $checkResult = [PSCustomObject]@{
        Category = $Category
        CheckName = $CheckName
        Description = $Description
        Result = $Result
        ExpectedValue = $ExpectedValue
        ActualValue = $ActualValue
        Severity = $Severity
        Recommendation = $Recommendation
        Reference = $Reference
    }
    
    # Add to appropriate category in results
    switch ($Category) {
        "Account Policies" { $Results.AccountPolicies += $checkResult }
        "Local Policies" { $Results.LocalPolicies += $checkResult }
        "Audit Policies" { $Results.AuditPolicies += $checkResult }
        "Registry Settings" { $Results.RegistrySettings += $checkResult }
        "Services" { $Results.ServicesCheck += $checkResult }
        "Network Settings" { $Results.NetworkSettings += $checkResult }
        "Advanced Settings" { $Results.AdvancedSettings += $checkResult }
    }
    
    # Update summary counts
    $Results.Summary.TotalChecks++
    
    if ($Result -eq "Pass") {
        $Results.Summary.PassedChecks++
        $logLevel = "Success"
    }
    elseif ($Result -eq "Fail") {
        $Results.Summary.FailedChecks++
        $logLevel = "Error"
    }
    else {
        $Results.Summary.WarningChecks++
        $logLevel = "Warning"
    }
    
    # Log the check
    Write-Log -Message "[$Category] $CheckName - $Result" -Level $logLevel
    
    return $checkResult
}

# Function to get system information
function Get-SystemInformation {
    Write-Log -Message "Gathering system information..." -Level "Info"
    
    try {
        $osInfo = Get-WmiObject -Class Win32_OperatingSystem
        $Results.ComputerInfo.OSVersion = $osInfo.Caption
        $Results.ComputerInfo.LastBootTime = $osInfo.LastBootUpTime
        
        # Check if this is a server OS
        $Results.ComputerInfo.IsServer = $osInfo.Caption -like "*Server*"
        
        # Get IP Addresses
        $ipConfig = Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
        foreach ($adapter in $ipConfig) {
            if ($adapter.IPAddress) {
                $Results.ComputerInfo.IPAddresses += $adapter.IPAddress
            }
        }
        
        Write-Log -Message "System information gathered successfully" -Level "Success"
        Write-Log -Message "Computer: $($Results.ComputerInfo.ComputerName), OS: $($Results.ComputerInfo.OSVersion)" -Level "Info"
        Write-Log -Message "Is Server OS: $($Results.ComputerInfo.IsServer)" -Level "Info"
    }
    catch {
        Write-Log -Message "Error gathering system information: $_" -Level "Error"
    }
}

# Function to check account policies
function Test-AccountPolicies {
    Write-Log -Message "Checking account policies..." -Level "Info"
    
    try {
        # Get net accounts settings
        $netAccounts = net accounts | Out-String
        
        # Password Policies
        
        # Password History
        $pattern = "Password history retained:\s+(\d+)"
        if ($netAccounts -match $pattern) {
            $actualValue = $matches[1]
            $expectedValue = "24"
            
            if ([int]$actualValue -ge [int]$expectedValue) {
                Add-CheckResult -Category "Account Policies" -CheckName "Password History" `
                    -Description "Ensures that a number of previous passwords are remembered to prevent password reuse" `
                    -Result "Pass" -ExpectedValue ">= $expectedValue" -ActualValue $actualValue -Severity "Medium" `
                    -Recommendation "Maintain or increase the password history setting" `
                    -Reference "CIS 1.1.1"
            }
            else {
                Add-CheckResult -Category "Account Policies" -CheckName "Password History" `
                    -Description "Ensures that a number of previous passwords are remembered to prevent password reuse" `
                    -Result "Fail" -ExpectedValue ">= $expectedValue" -ActualValue $actualValue -Severity "Medium" `
                    -Recommendation "Increase password history to at least 24 passwords" `
                    -Reference "CIS 1.1.1"
            }
        }
        
        # Maximum Password Age
        $pattern = "Maximum password age \(days\):\s+(\d+)"
        if ($netAccounts -match $pattern) {
            $actualValue = $matches[1]
            $expectedMin = "60"
            $expectedMax = "90"
            
            if ([int]$actualValue -le [int]$expectedMax -and [int]$actualValue -ge [int]$expectedMin) {
                Add-CheckResult -Category "Account Policies" -CheckName "Maximum Password Age" `
                    -Description "Ensures that passwords expire at regular intervals" `
                    -Result "Pass" -ExpectedValue "Between $expectedMin and $expectedMax days" -ActualValue "$actualValue days" -Severity "Medium" `
                    -Recommendation "Maintain current password age policy" `
                    -Reference "CIS 1.1.2"
            }
            elseif ([int]$actualValue -eq 0) {
                Add-CheckResult -Category "Account Policies" -CheckName "Maximum Password Age" `
                    -Description "Ensures that passwords expire at regular intervals" `
                    -Result "Fail" -ExpectedValue "Between $expectedMin and $expectedMax days" -ActualValue "Never expires ($actualValue days)" -Severity "High" `
                    -Recommendation "Configure maximum password age to between 60 and 90 days" `
                    -Reference "CIS 1.1.2"
            }
            else {
                Add-CheckResult -Category "Account Policies" -CheckName "Maximum Password Age" `
                    -Description "Ensures that passwords expire at regular intervals" `
                    -Result "Warning" -ExpectedValue "Between $expectedMin and $expectedMax days" -ActualValue "$actualValue days" -Severity "Medium" `
                    -Recommendation "Configure maximum password age to between 60 and 90 days" `
                    -Reference "CIS 1.1.2"
            }
        }
        
        # Minimum Password Age
        $pattern = "Minimum password age \(days\):\s+(\d+)"
        if ($netAccounts -match $pattern) {
            $actualValue = $matches[1]
            $expectedValue = "1"
            
            if ([int]$actualValue -ge [int]$expectedValue) {
                Add-CheckResult -Category "Account Policies" -CheckName "Minimum Password Age" `
                    -Description "Ensures that passwords cannot be changed too frequently to bypass password history" `
                    -Result "Pass" -ExpectedValue ">= $expectedValue" -ActualValue $actualValue -Severity "Medium" `
                    -Recommendation "Maintain or increase the minimum password age setting" `
                    -Reference "CIS 1.1.3"
            }
            else {
                Add-CheckResult -Category "Account Policies" -CheckName "Minimum Password Age" `
                    -Description "Ensures that passwords cannot be changed too frequently to bypass password history" `
                    -Result "Fail" -ExpectedValue ">= $expectedValue" -ActualValue $actualValue -Severity "Medium" `
                    -Recommendation "Configure minimum password age to at least 1 day" `
                    -Reference "CIS 1.1.3"
            }
        }
        
        # Minimum Password Length
        $pattern = "Minimum password length:\s+(\d+)"
        if ($netAccounts -match $pattern) {
            $actualValue = $matches[1]
            $expectedValue = "14"
            
            if ([int]$actualValue -ge [int]$expectedValue) {
                Add-CheckResult -Category "Account Policies" -CheckName "Minimum Password Length" `
                    -Description "Ensures that passwords are sufficiently complex" `
                    -Result "Pass" -ExpectedValue ">= $expectedValue" -ActualValue $actualValue -Severity "High" `
                    -Recommendation "Maintain current minimum password length" `
                    -Reference "CIS 1.1.4"
            }
            else {
                Add-CheckResult -Category "Account Policies" -CheckName "Minimum Password Length" `
                    -Description "Ensures that passwords are sufficiently complex" `
                    -Result "Fail" -ExpectedValue ">= $expectedValue" -ActualValue $actualValue -Severity "High" `
                    -Recommendation "Increase minimum password length to at least 14 characters" `
                    -Reference "CIS 1.1.4"
            }
        }
        
        # Password Complexity
        $secpolContent = secedit /export /areas SECURITYPOLICY /cfg C:\Windows\Temp\secpol.cfg
        $secpolContent = Get-Content C:\Windows\Temp\secpol.cfg
        
        $pattern = "PasswordComplexity\s+=\s+(\d+)"
        $match = $secpolContent | Where-Object { $_ -match $pattern }
        
        if ($match) {
            $actualValue = $matches[1]
            $expectedValue = "1"
            
            if ($actualValue -eq $expectedValue) {
                Add-CheckResult -Category "Account Policies" -CheckName "Password Complexity" `
                    -Description "Ensures that passwords meet complexity requirements" `
                    -Result "Pass" -ExpectedValue "Enabled" -ActualValue "Enabled" -Severity "High" `
                    -Recommendation "Maintain password complexity requirement" `
                    -Reference "CIS 1.1.5"
            }
            else {
                Add-CheckResult -Category "Account Policies" -CheckName "Password Complexity" `
                    -Description "Ensures that passwords meet complexity requirements" `
                    -Result "Fail" -ExpectedValue "Enabled" -ActualValue "Disabled" -Severity "High" `
                    -Recommendation "Enable password complexity requirements" `
                    -Reference "CIS 1.1.5"
            }
        }
        
        # Account Lockout Policies
        
        # Account Lockout Threshold
        $pattern = "Lockout threshold:\s+(\d+)"
        if ($netAccounts -match $pattern) {
            $actualValue = $matches[1]
            $expectedMin = "3"
            $expectedMax = "10"
            
            if ([int]$actualValue -gt 0 -and [int]$actualValue -le [int]$expectedMax -and [int]$actualValue -ge [int]$expectedMin) {
                Add-CheckResult -Category "Account Policies" -CheckName "Account Lockout Threshold" `
                    -Description "Ensures that accounts are locked after a number of failed login attempts" `
                    -Result "Pass" -ExpectedValue "Between $expectedMin and $expectedMax" -ActualValue $actualValue -Severity "High" `
                    -Recommendation "Maintain current account lockout threshold" `
                    -Reference "CIS 1.2.1"
            }
            elseif ([int]$actualValue -eq 0) {
                Add-CheckResult -Category "Account Policies" -CheckName "Account Lockout Threshold" `
                    -Description "Ensures that accounts are locked after a number of failed login attempts" `
                    -Result "Fail" -ExpectedValue "Between $expectedMin and $expectedMax" -ActualValue "Never (0)" -Severity "High" `
                    -Recommendation "Configure account lockout threshold to between 3 and 10 failed attempts" `
                    -Reference "CIS 1.2.1"
            }
            else {
                Add-CheckResult -Category "Account Policies" -CheckName "Account Lockout Threshold" `
                    -Description "Ensures that accounts are locked after a number of failed login attempts" `
                    -Result "Warning" -ExpectedValue "Between $expectedMin and $expectedMax" -ActualValue $actualValue -Severity "Medium" `
                    -Recommendation "Consider adjusting account lockout threshold to between 3 and 10 failed attempts" `
                    -Reference "CIS 1.2.1"
            }
        }
        
        # Account Lockout Duration
        $pattern = "Lockout duration \(minutes\):\s+(\d+)"
        if ($netAccounts -match $pattern) {
            $actualValue = $matches[1]
            $expectedMin = "15"
            
            if ([int]$actualValue -ge [int]$expectedMin) {
                Add-CheckResult -Category "Account Policies" -CheckName "Account Lockout Duration" `
                    -Description "Ensures that locked accounts remain locked for a sufficient time period" `
                    -Result "Pass" -ExpectedValue ">= $expectedMin minutes" -ActualValue "$actualValue minutes" -Severity "Medium" `
                    -Recommendation "Maintain current account lockout duration" `
                    -Reference "CIS 1.2.2"
            }
            else {
                Add-CheckResult -Category "Account Policies" -CheckName "Account Lockout Duration" `
                    -Description "Ensures that locked accounts remain locked for a sufficient time period" `
                    -Result "Fail" -ExpectedValue ">= $expectedMin minutes" -ActualValue "$actualValue minutes" -Severity "Medium" `
                    -Recommendation "Increase account lockout duration to at least 15 minutes" `
                    -Reference "CIS 1.2.2"
            }
        }
        
        # Reset Account Lockout Counter
        $pattern = "Lockout observation window \(minutes\):\s+(\d+)"
        if ($netAccounts -match $pattern) {
            $actualValue = $matches[1]
            $expectedMin = "15"
            
            if ([int]$actualValue -ge [int]$expectedMin) {
                Add-CheckResult -Category "Account Policies" -CheckName "Reset Account Lockout Counter" `
                    -Description "Ensures that the failed login counter resets after a sufficient time period" `
                    -Result "Pass" -ExpectedValue ">= $expectedMin minutes" -ActualValue "$actualValue minutes" -Severity "Medium" `
                    -Recommendation "Maintain current account lockout reset counter setting" `
                    -Reference "CIS 1.2.3"
            }
            else {
                Add-CheckResult -Category "Account Policies" -CheckName "Reset Account Lockout Counter" `
                    -Description "Ensures that the failed login counter resets after a sufficient time period" `
                    -Result "Fail" -ExpectedValue ">= $expectedMin minutes" -ActualValue "$actualValue minutes" -Severity "Medium" `
                    -Recommendation "Increase reset account lockout counter setting to at least 15 minutes" `
                    -Reference "CIS 1.2.3"
            }
        }
        
        Remove-Item C:\Windows\Temp\secpol.cfg -Force -ErrorAction SilentlyContinue
    }
    catch {
        Write-Log -Message "Error checking account policies: $_" -Level "Error"
    }
}

# Function to check local security policies
function Test-LocalSecurityPolicies {
    Write-Log -Message "Checking local security policies..." -Level "Info"
    
    try {
        # Export local security policy for analysis
        $secpol = secedit /export /areas SECURITYPOLICY /cfg C:\Windows\Temp\secpol.cfg
        $secpolContent = Get-Content C:\Windows\Temp\secpol.cfg
        
        # Check Administrator Account Status
        $pattern = "EnableAdminAccount\s+=\s+(\d+)"
        $match = $secpolContent | Where-Object { $_ -match $pattern }
        
        if ($match) {
            $actualValue = $matches[1]
            $expectedValue = "0"
            
            if ($actualValue -eq $expectedValue) {
                Add-CheckResult -Category "Local Policies" -CheckName "Administrator Account Status" `
                    -Description "Ensures that the built-in Administrator account is disabled" `
                    -Result "Pass" -ExpectedValue "Disabled" -ActualValue "Disabled" -Severity "High" `
                    -Recommendation "Maintain the Administrator account as disabled" `
                    -Reference "CIS 2.3.1.1"
            }
            else {
                Add-CheckResult -Category "Local Policies" -CheckName "Administrator Account Status" `
                    -Description "Ensures that the built-in Administrator account is disabled" `
                    -Result "Fail" -ExpectedValue "Disabled" -ActualValue "Enabled" -Severity "High" `
                    -Recommendation "Disable the built-in Administrator account" `
                    -Reference "CIS 2.3.1.1"
            }
        }
        
        # Check Guest Account Status
        $pattern = "EnableGuestAccount\s+=\s+(\d+)"
        $match = $secpolContent | Where-Object { $_ -match $pattern }
        
        if ($match) {
            $actualValue = $matches[1]
            $expectedValue = "0"
            
            if ($actualValue -eq $expectedValue) {
                Add-CheckResult -Category "Local Policies" -CheckName "Guest Account Status" `
                    -Description "Ensures that the built-in Guest account is disabled" `
                    -Result "Pass" -ExpectedValue "Disabled" -ActualValue "Disabled" -Severity "High" `
                    -Recommendation "Maintain the Guest account as disabled" `
                    -Reference "CIS 2.3.1.2"
            }
            else {
                Add-CheckResult -Category "Local Policies" -CheckName "Guest Account Status" `
                    -Description "Ensures that the built-in Guest account is disabled" `
                    -Result "Fail" -ExpectedValue "Disabled" -ActualValue "Enabled" -Severity "High" `
                    -Recommendation "Disable the built-in Guest account" `
                    -Reference "CIS 2.3.1.2"
            }
        }
        
        # Check Access from Network
        $pattern = "SeDenyNetworkLogonRight\s+=\s+(.*)"
        $match = $secpolContent | Where-Object { $_ -match $pattern }
        
        if ($match) {
            $actualValue = $matches[1]
            $guestInList = $actualValue -like "*S-1-5-32-546*" # Guest SID
            
            if ($guestInList) {
                Add-CheckResult -Category "Local Policies" -CheckName "Deny Access from Network" `
                    -Description "Ensures that the Guest account cannot access the computer from the network" `
                    -Result "Pass" -ExpectedValue "Guest account listed" -ActualValue "Guest account listed" -Severity "High" `
                    -Recommendation "Maintain current Deny Network Access setting" `
                    -Reference "CIS 2.3.7.1"
            }
            else {
                Add-CheckResult -Category "Local Policies" -CheckName "Deny Access from Network" `
                    -Description "Ensures that the Guest account cannot access the computer from the network" `
                    -Result "Fail" -ExpectedValue "Guest account listed" -ActualValue "Guest account not listed" -Severity "High" `
                    -Recommendation "Add the Guest account to 'Deny access to this computer from the network'" `
                    -Reference "CIS 2.3.7.1"
            }
        }
        else {
            Add-CheckResult -Category "Local Policies" -CheckName "Deny Access from Network" `
                -Description "Ensures that the Guest account cannot access the computer from the network" `
                -Result "Fail" -ExpectedValue "Guest account listed" -ActualValue "Policy not configured" -Severity "High" `
                -Recommendation "Configure 'Deny access to this computer from the network' to include the Guest account" `
                -Reference "CIS 2.3.7.1"
        }
        
        # Check Local Administrator enumeration
        $pattern = "EnableAdminAccount\s+=\s+(\d+)"
        $match = $secpolContent | Where-Object { $_ -match $pattern }
        
        if ($match) {
            # Check Renamed Administrator Account
            $lsaKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            $forceGuest = (Get-ItemProperty -Path $lsaKey -Name "forceguest" -ErrorAction SilentlyContinue).forceguest
            
            if ($null -ne $forceGuest -and $forceGuest -eq 0) {
                Add-CheckResult -Category "Local Policies" -CheckName "Network Access Model" `
                    -Description "Ensures that network access model is set to Classic" `
                    -Result "Pass" -ExpectedValue "Classic - local users authenticate as themselves" -ActualValue "Classic - local users authenticate as themselves" -Severity "Medium" `
                    -Recommendation "Maintain current network access model setting" `
                    -Reference "CIS 2.3.9.1"
            }
            else {
                Add-CheckResult -Category "Local Policies" -CheckName "Network Access Model" `
                    -Description "Ensures that network access model is set to Classic" `
                    -Result "Fail" -ExpectedValue "Classic - local users authenticate as themselves" -ActualValue "Guest only - local users authenticate as Guest" -Severity "Medium" `
                    -Recommendation "Configure 'Network access: Sharing and security model for local accounts' to 'Classic'" `
                    -Reference "CIS 2.3.9.1"
            }
        }
        
        # Check User Account Control Settings
        $uacKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        
        # Check UAC Elevation Prompt for Admins
        $consentPromptBehaviorAdmin = (Get-ItemProperty -Path $uacKey -Name "ConsentPromptBehaviorAdmin" -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin
        
        if ($null -ne $consentPromptBehaviorAdmin) {
            switch ($consentPromptBehaviorAdmin) {
                0 {
                    $actualValue = "Elevate without prompting"
                    $result = "Fail"
                }
                1 {
                    $actualValue = "Prompt for credentials on the secure desktop"
                    $result = "Pass"
                }
                2 {
                    $actualValue = "Prompt for consent on the secure desktop"
                    $result = "Pass"
                }
                3 {
                    $actualValue = "Prompt for credentials"
                    $result = "Warning"
                }
                4 {
                    $actualValue = "Prompt for consent"
                    $result = "Warning"
                }
                5 {
                    $actualValue = "Prompt for consent for non-Windows binaries"
                    $result = "Warning"
                }
                default {
                    $actualValue = "Unknown ($consentPromptBehaviorAdmin)"
                    $result = "Warning"
                }
            }
            
            Add-CheckResult -Category "Local Policies" -CheckName "UAC Elevation Prompt for Administrators" `
                -Description "Ensures that UAC prompts administrators for consent on the secure desktop" `
                -Result $result -ExpectedValue "Prompt for consent/credentials on the secure desktop" -ActualValue $actualValue -Severity "High" `
                -Recommendation "Configure 'User Account Control: Behavior of the elevation prompt for administrators' to 'Prompt for consent on the secure desktop'" `
                -Reference "CIS 2.3.17.1"
        }
        else {
            Add-CheckResult -Category "Local Policies" -CheckName "UAC Elevation Prompt for Administrators" `
                -Description "Ensures that UAC prompts administrators for consent on the secure desktop" `
                -Result "Warning" -ExpectedValue "Prompt for consent/credentials on the secure desktop" -ActualValue "Not configured" -Severity "High" `
                -Recommendation "Configure 'User Account Control: Behavior of the elevation prompt for administrators' to 'Prompt for consent on the secure desktop'" `
                -Reference "CIS 2.3.17.1"
        }
        
        # Check UAC Elevation Prompt for Standard Users
        $consentPromptBehaviorUser = (Get-ItemProperty -Path $uacKey -Name "ConsentPromptBehaviorUser" -ErrorAction SilentlyContinue).ConsentPromptBehaviorUser
        
        if ($null -ne $consentPromptBehaviorUser) {
            switch ($consentPromptBehaviorUser) {
                0 {
                    $actualValue = "Automatically deny elevation requests"
                    $result = "Fail"
                }
                1 {
                    $actualValue = "Prompt for credentials on the secure desktop"
                    $result = "Pass"
                }
                3 {
                    $actualValue = "Prompt for credentials"
                    $result = "Warning"
                }
                default {
                    $actualValue = "Unknown ($consentPromptBehaviorUser)"
                    $result = "Warning"
                }
            }
            
            Add-CheckResult -Category "Local Policies" -CheckName "UAC Elevation Prompt for Standard Users" `
                -Description "Ensures that UAC prompts standard users for credentials on the secure desktop" `
                -Result $result -ExpectedValue "Prompt for credentials on the secure desktop" -ActualValue $actualValue -Severity "High" `
                -Recommendation "Configure 'User Account Control: Behavior of the elevation prompt for standard users' to 'Prompt for credentials on the secure desktop'" `
                -Reference "CIS 2.3.17.2"
        }
        else {
            Add-CheckResult -Category "Local Policies" -CheckName "UAC Elevation Prompt for Standard Users" `
                -Description "Ensures that UAC prompts standard users for credentials on the secure desktop" `
                -Result "Warning" -ExpectedValue "Prompt for credentials on the secure desktop" -ActualValue "Not configured" -Severity "High" `
                -Recommendation "Configure 'User Account Control: Behavior of the elevation prompt for standard users' to 'Prompt for credentials on the secure desktop'" `
                -Reference "CIS 2.3.17.2"
        }
        
        # Check UAC Enabled
        $enableLUA = (Get-ItemProperty -Path $uacKey -Name "EnableLUA" -ErrorAction SilentlyContinue).EnableLUA
        
        if ($null -ne $enableLUA) {
            $actualValue = if ($enableLUA -eq 1) { "Enabled" } else { "Disabled" }
            $result = if ($enableLUA -eq 1) { "Pass" } else { "Fail" }
            
            Add-CheckResult -Category "Local Policies" -CheckName "UAC Enabled" `
                -Description "Ensures that User Account Control is enabled" `
                -Result $result -ExpectedValue "Enabled" -ActualValue $actualValue -Severity "High" `
                -Recommendation "Configure 'User Account Control: Run all administrators in Admin Approval Mode' to 'Enabled'" `
                -Reference "CIS 2.3.17.6"
        }
        else {
            Add-CheckResult -Category "Local Policies" -CheckName "UAC Enabled" `
                -Description "Ensures that User Account Control is enabled" `
                -Result "Warning" -ExpectedValue "Enabled" -ActualValue "Not configured" -Severity "High" `
                -Recommendation "Configure 'User Account Control: Run all administrators in Admin Approval Mode' to 'Enabled'" `
                -Reference "CIS 2.3.17.6"
        }
        
        Remove-Item C:\Windows\Temp\secpol.cfg -Force -ErrorAction SilentlyContinue
    }
    catch {
        Write-Log -Message "Error checking local security policies: $_" -Level "Error"
    }
}

# Function to check audit policies
function Test-AuditPolicies {
    Write-Log -Message "Checking audit policies..." -Level "Info"
    
    try {
        # Get audit policy settings
        $auditpol = auditpol /get /category:* /r | ConvertFrom-Csv
        
        # Account Logon
        $credValidation = ($auditpol | Where-Object { $_."Subcategory" -eq "Credential Validation" })."Inclusion Setting"
        
        if ($credValidation -eq "Success and Failure") {
            Add-CheckResult -Category "Audit Policies" -CheckName "Audit Credential Validation" `
                -Description "Ensures that credential validation is audited" `
                -Result "Pass" -ExpectedValue "Success and Failure" -ActualValue $credValidation -Severity "High" `
                -Recommendation "Maintain current audit policy for credential validation" `
                -Reference "CIS 17.1.1"
        }
        elseif ($credValidation -eq "Failure") {
            Add-CheckResult -Category "Audit Policies" -CheckName "Audit Credential Validation" `
                -Description "Ensures that credential validation is audited" `
                -Result "Warning" -ExpectedValue "Success and Failure" -ActualValue $credValidation -Severity "High" `
                -Recommendation "Configure 'Audit: Credential Validation' to 'Success and Failure'" `
                -Reference "CIS 17.1.1"
        }
        else {
            Add-CheckResult -Category "Audit Policies" -CheckName "Audit Credential Validation" `
                -Description "Ensures that credential validation is audited" `
                -Result "Fail" -ExpectedValue "Success and Failure" -ActualValue $credValidation -Severity "High" `
                -Recommendation "Configure 'Audit: Credential Validation' to 'Success and Failure'" `
                -Reference "CIS 17.1.1"
        }
        
        # Logon/Logoff
        $logon = ($auditpol | Where-Object { $_."Subcategory" -eq "Logon" })."Inclusion Setting"
        
        if ($logon -eq "Success and Failure") {
            Add-CheckResult -Category "Audit Policies" -CheckName "Audit Logon" `
                -Description "Ensures that logon events are audited" `
                -Result "Pass" -ExpectedValue "Success and Failure" -ActualValue $logon -Severity "High" `
                -Recommendation "Maintain current audit policy for logon events" `
                -Reference "CIS 17.5.1"
        }
        elseif ($logon -match "Success|Failure") {
            Add-CheckResult -Category "Audit Policies" -CheckName "Audit Logon" `
                -Description "Ensures that logon events are audited" `
                -Result "Warning" -ExpectedValue "Success and Failure" -ActualValue $logon -Severity "High" `
                -Recommendation "Configure 'Audit: Logon' to 'Success and Failure'" `
                -Reference "CIS 17.5.1"
        }
        else {
            Add-CheckResult -Category "Audit Policies" -CheckName "Audit Logon" `
                -Description "Ensures that logon events are audited" `
                -Result "Fail" -ExpectedValue "Success and Failure" -ActualValue $logon -Severity "High" `
                -Recommendation "Configure 'Audit: Logon' to 'Success and Failure'" `
                -Reference "CIS 17.5.1"
        }
        
        # Account Management
        $userAccountManagement = ($auditpol | Where-Object { $_."Subcategory" -eq "User Account Management" })."Inclusion Setting"
        
        if ($userAccountManagement -eq "Success and Failure") {
            Add-CheckResult -Category "Audit Policies" -CheckName "Audit User Account Management" `
                -Description "Ensures that user account management events are audited" `
                -Result "Pass" -ExpectedValue "Success and Failure" -ActualValue $userAccountManagement -Severity "High" `
                -Recommendation "Maintain current audit policy for user account management" `
                -Reference "CIS 17.2.1"
        }
        elseif ($userAccountManagement -match "Success|Failure") {
            Add-CheckResult -Category "Audit Policies" -CheckName "Audit User Account Management" `
                -Description "Ensures that user account management events are audited" `
                -Result "Warning" -ExpectedValue "Success and Failure" -ActualValue $userAccountManagement -Severity "High" `
                -Recommendation "Configure 'Audit: User Account Management' to 'Success and Failure'" `
                -Reference "CIS 17.2.1"
        }
        else {
            Add-CheckResult -Category "Audit Policies" -CheckName "Audit User Account Management" `
                -Description "Ensures that user account management events are audited" `
                -Result "Fail" -ExpectedValue "Success and Failure" -ActualValue $userAccountManagement -Severity "High" `
                -Recommendation "Configure 'Audit: User Account Management' to 'Success and Failure'" `
                -Reference "CIS 17.2.1"
        }
        
        # Object Access
        $fileSystem = ($auditpol | Where-Object { $_."Subcategory" -eq "File System" })."Inclusion Setting"
        
        if ($fileSystem -match "Success|Failure") {
            Add-CheckResult -Category "Audit Policies" -CheckName "Audit File System" `
                -Description "Ensures that file system access is audited where needed" `
                -Result "Pass" -ExpectedValue "Configured where needed" -ActualValue $fileSystem -Severity "Medium" `
                -Recommendation "Maintain appropriate audit settings for file system access" `
                -Reference "CIS 17.6.1"
        }
        else {
            Add-CheckResult -Category "Audit Policies" -CheckName "Audit File System" `
                -Description "Ensures that file system access is audited where needed" `
                -Result "Warning" -ExpectedValue "Configured where needed" -ActualValue $fileSystem -Severity "Medium" `
                -Recommendation "Consider configuring auditing for sensitive file system objects" `
                -Reference "CIS 17.6.1"
        }
    }
    catch {
        Write-Log -Message "Error checking audit policies: $_" -Level "Error"
    }
}

# Function to check registry settings
function Test-RegistrySettings {
    Write-Log -Message "Checking registry settings..." -Level "Info"
    
    try {
        # Check Remote Registry Service Status
        $remoteRegistry = Get-Service -Name "RemoteRegistry" -ErrorAction SilentlyContinue
        
        if ($remoteRegistry) {
            $status = $remoteRegistry.Status
            $startType = $remoteRegistry.StartType
            
            if ($startType -eq "Disabled") {
                Add-CheckResult -Category "Registry Settings" -CheckName "Remote Registry Service" `
                    -Description "Ensures that the Remote Registry service is disabled" `
                    -Result "Pass" -ExpectedValue "Disabled" -ActualValue "Disabled" -Severity "High" `
                    -Recommendation "Maintain the Remote Registry service as disabled" `
                    -Reference "CIS 5.1.1"
            }
            else {
                Add-CheckResult -Category "Registry Settings" -CheckName "Remote Registry Service" `
                    -Description "Ensures that the Remote Registry service is disabled" `
                    -Result "Fail" -ExpectedValue "Disabled" -ActualValue $startType -Severity "High" `
                    -Recommendation "Disable the Remote Registry service" `
                    -Reference "CIS 5.1.1"
            }
        }
        else {
            Add-CheckResult -Category "Registry Settings" -CheckName "Remote Registry Service" `
                -Description "Ensures that the Remote Registry service is disabled" `
                -Result "Warning" -ExpectedValue "Disabled" -ActualValue "Not Found" -Severity "High" `
                -Recommendation "Verify Remote Registry service existence and status" `
                -Reference "CIS 5.1.1"
        }
        
        # Check Windows Firewall Status
        $firewallKey = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"
        $domainProfile = "$firewallKey\DomainProfile"
        $publicProfile = "$firewallKey\PublicProfile"
        $standardProfile = "$firewallKey\StandardProfile"
        
        # Domain Profile
        $domainEnabled = (Get-ItemProperty -Path $domainProfile -Name "EnableFirewall" -ErrorAction SilentlyContinue).EnableFirewall
        
        if ($null -ne $domainEnabled) {
            $actualValue = if ($domainEnabled -eq 1) { "Enabled" } else { "Disabled" }
            $result = if ($domainEnabled -eq 1) { "Pass" } else { "Fail" }
            
            Add-CheckResult -Category "Registry Settings" -CheckName "Windows Firewall: Domain Profile" `
                -Description "Ensures that Windows Firewall is enabled for the domain profile" `
                -Result $result -ExpectedValue "Enabled" -ActualValue $actualValue -Severity "High" `
                -Recommendation "Enable Windows Firewall for the domain profile" `
                -Reference "CIS 9.1.1"
        }
        else {
            Add-CheckResult -Category "Registry Settings" -CheckName "Windows Firewall: Domain Profile" `
                -Description "Ensures that Windows Firewall is enabled for the domain profile" `
                -Result "Warning" -ExpectedValue "Enabled" -ActualValue "Not configured" -Severity "High" `
                -Recommendation "Enable Windows Firewall for the domain profile" `
                -Reference "CIS 9.1.1"
        }
        
        # Public Profile
        $publicEnabled = (Get-ItemProperty -Path $publicProfile -Name "EnableFirewall" -ErrorAction SilentlyContinue).EnableFirewall
        
        if ($null -ne $publicEnabled) {
            $actualValue = if ($publicEnabled -eq 1) { "Enabled" } else { "Disabled" }
            $result = if ($publicEnabled -eq 1) { "Pass" } else { "Fail" }
            
            Add-CheckResult -Category "Registry Settings" -CheckName "Windows Firewall: Public Profile" `
                -Description "Ensures that Windows Firewall is enabled for the public profile" `
                -Result $result -ExpectedValue "Enabled" -ActualValue $actualValue -Severity "High" `
                -Recommendation "Enable Windows Firewall for the public profile" `
                -Reference "CIS 9.2.1"
        }
        else {
            Add-CheckResult -Category "Registry Settings" -CheckName "Windows Firewall: Public Profile" `
                -Description "Ensures that Windows Firewall is enabled for the public profile" `
                -Result "Warning" -ExpectedValue "Enabled" -ActualValue "Not configured" -Severity "High" `
                -Recommendation "Enable Windows Firewall for the public profile" `
                -Reference "CIS 9.2.1"
        }
        
        # Standard Profile (Private)
        $standardEnabled = (Get-ItemProperty -Path $standardProfile -Name "EnableFirewall" -ErrorAction SilentlyContinue).EnableFirewall
        
        if ($null -ne $standardEnabled) {
            $actualValue = if ($standardEnabled -eq 1) { "Enabled" } else { "Disabled" }
            $result = if ($standardEnabled -eq 1) { "Pass" } else { "Fail" }
            
            Add-CheckResult -Category "Registry Settings" -CheckName "Windows Firewall: Private Profile" `
                -Description "Ensures that Windows Firewall is enabled for the private profile" `
                -Result $result -ExpectedValue "Enabled" -ActualValue $actualValue -Severity "High" `
                -Recommendation "Enable Windows Firewall for the private profile" `
                -Reference "CIS 9.3.1"
        }
        else {
            Add-CheckResult -Category "Registry Settings" -CheckName "Windows Firewall: Private Profile" `
                -Description "Ensures that Windows Firewall is enabled for the private profile" `
                -Result "Warning" -ExpectedValue "Enabled" -ActualValue "Not configured" -Severity "High" `
                -Recommendation "Enable Windows Firewall for the private profile" `
                -Reference "CIS 9.3.1"
        }
        
        # Check Autoplay and Autorun
        $autoplayKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        $autoplayEnabled = (Get-ItemProperty -Path $autoplayKey -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue).NoDriveTypeAutoRun
        
        if ($null -ne $autoplayEnabled) {
            $actualValue = if ($autoplayEnabled -eq 255) { "Disabled for all drives" } else { "Enabled for some drives" }
            $result = if ($autoplayEnabled -eq 255) { "Pass" } else { "Warning" }
            
            Add-CheckResult -Category "Registry Settings" -CheckName "Autoplay and Autorun" `
                -Description "Ensures that Autoplay is disabled for all drives" `
                -Result $result -ExpectedValue "Disabled for all drives" -ActualValue $actualValue -Severity "Medium" `
                -Recommendation "Disable Autoplay for all drives" `
                -Reference "CIS 18.8.1"
        }
        else {
            Add-CheckResult -Category "Registry Settings" -CheckName "Autoplay and Autorun" `
                -Description "Ensures that Autoplay is disabled for all drives" `
                -Result "Fail" -ExpectedValue "Disabled for all drives" -ActualValue "Not configured" -Severity "Medium" `
                -Recommendation "Disable Autoplay for all drives" `
                -Reference "CIS 18.8.1"
        }
        
        # Check Windows Update Settings
        $wuKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
        $wuEnabled = (Get-ItemProperty -Path $wuKey -Name "NoAutoUpdate" -ErrorAction SilentlyContinue).NoAutoUpdate
        
        if ($null -ne $wuEnabled) {
            $actualValue = if ($wuEnabled -eq 0) { "Enabled" } else { "Disabled" }
            $result = if ($wuEnabled -eq 0) { "Pass" } else { "Fail" }
            
            Add-CheckResult -Category "Registry Settings" -CheckName "Windows Update: Automatic Updates" `
                -Description "Ensures that Windows automatic updates are enabled" `
                -Result $result -ExpectedValue "Enabled" -ActualValue $actualValue -Severity "High" `
                -Recommendation "Enable Windows automatic updates" `
                -Reference "CIS 18.9.85.1"
        }
        else {
            # Check using non-policy registry key as fallback
            $wuKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update"
            $auOptions = (Get-ItemProperty -Path $wuKey -Name "AUOptions" -ErrorAction SilentlyContinue).AUOptions
            
            if ($null -ne $auOptions) {
                $actualValue = switch ($auOptions) {
                    1 { "Never check for updates" }
                    2 { "Check for updates but let me choose whether to download and install them" }
                    3 { "Download updates but let me choose whether to install them" }
                    4 { "Install updates automatically" }
                    5 { "Allow local admin to choose setting" }
                    default { "Unknown setting: $auOptions" }
                }
                
                $result = if ($auOptions -eq 4) { "Pass" } elseif ($auOptions -in @(2, 3, 5)) { "Warning" } else { "Fail" }
                
                Add-CheckResult -Category "Registry Settings" -CheckName "Windows Update: Automatic Updates" `
                    -Description "Ensures that Windows automatic updates are enabled" `
                    -Result $result -ExpectedValue "Install updates automatically" -ActualValue $actualValue -Severity "High" `
                    -Recommendation "Configure Windows automatic updates to install automatically" `
                    -Reference "CIS 18.9.85.1"
            }
            else {
                Add-CheckResult -Category "Registry Settings" -CheckName "Windows Update: Automatic Updates" `
                    -Description "Ensures that Windows automatic updates are enabled" `
                    -Result "Warning" -ExpectedValue "Enabled" -ActualValue "Not configured" -Severity "High" `
                    -Recommendation "Enable Windows automatic updates" `
                    -Reference "CIS 18.9.85.1"
            }
        }
    }
    catch {
        Write-Log -Message "Error checking registry settings: $_" -Level "Error"
    }
}

# Function to check services
function Test-Services {
    Write-Log -Message "Checking services..." -Level "Info"
    
    try {
        # List of services that should be disabled
        $servicesToDisable = @{
            "Browser" = "Computer Browser"
            "SharedAccess" = "Internet Connection Sharing (ICS)"
            "IpHlpSvc" = "IP Helper" # Needed for IPv6
            "lmhosts" = "TCP/IP NetBIOS Helper"
            "wercplsupport" = "Problem Reports and Solutions Control Panel"
            "SCardSvr" = "Smart Card"
            "SNMPTRAP" = "SNMP Trap"
            "LanmanServer" = "Server" # Only for non-file servers
            "upnphost" = "UPnP Device Host"
            "WerSvc" = "Windows Error Reporting Service"
            "Wecsvc" = "Windows Event Collector"
            "WpnService" = "Windows Push Notifications System Service"
            "TrkWks" = "Distributed Link Tracking Client"
            "PeerDistSvc" = "BranchCache"
        }
        
        foreach ($service in $servicesToDisable.GetEnumerator()) {
            $serviceName = $service.Key
            $displayName = $service.Value
            
            # Skip certain checks for server or workstation based on configuration
            if ($CheckServerOnly -and $Results.ComputerInfo.IsServer -eq $false) {
                if ($serviceName -in @("LanmanServer")) {
                    continue
                }
            }
            
            $serviceObj = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            
            if ($serviceObj) {
                $startType = $serviceObj.StartType
                $status = $serviceObj.Status
                
                if ($startType -eq "Disabled") {
                    Add-CheckResult -Category "Services" -CheckName "$displayName Service" `
                        -Description "Ensures that the $displayName service is disabled" `
                        -Result "Pass" -ExpectedValue "Disabled" -ActualValue "Disabled" -Severity "Medium" `
                        -Recommendation "Maintain $displayName service as disabled" `
                        -Reference "CIS 5.1"
                }
                else {
                    Add-CheckResult -Category "Services" -CheckName "$displayName Service" `
                        -Description "Ensures that the $displayName service is disabled" `
                        -Result "Fail" -ExpectedValue "Disabled" -ActualValue $startType -Severity "Medium" `
                        -Recommendation "Disable the $displayName service" `
                        -Reference "CIS 5.1"
                }
            }
            else {
                Add-CheckResult -Category "Services" -CheckName "$displayName Service" `
                    -Description "Ensures that the $displayName service is disabled" `
                    -Result "Pass" -ExpectedValue "Disabled or Not Installed" -ActualValue "Not Installed" -Severity "Medium" `
                    -Recommendation "No action required" `
                    -Reference "CIS 5.1"
            }
        }
        
        # Services that should be running
        $servicesToEnable = @{
            "EventLog" = "Windows Event Log"
            "mpssvc" = "Windows Firewall"
            "WinDefend" = "Windows Defender"
        }
        
        foreach ($service in $servicesToEnable.GetEnumerator()) {
            $serviceName = $service.Key
            $displayName = $service.Value
            
            $serviceObj = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            
            if ($serviceObj) {
                $startType = $serviceObj.StartType
                $status = $serviceObj.Status
                
                if ($startType -in @("Automatic", "AutomaticDelayedStart") -and $status -eq "Running") {
                    Add-CheckResult -Category "Services" -CheckName "$displayName Service" `
                        -Description "Ensures that the $displayName service is enabled and running" `
                        -Result "Pass" -ExpectedValue "Automatic and Running" -ActualValue "$startType and $status" -Severity "High" `
                        -Recommendation "Maintain $displayName service as enabled and running" `
                        -Reference "CIS 5.2"
                }
                elseif ($startType -in @("Automatic", "AutomaticDelayedStart") -and $status -ne "Running") {
                    Add-CheckResult -Category "Services" -CheckName "$displayName Service" `
                        -Description "Ensures that the $displayName service is enabled and running" `
                        -Result "Warning" -ExpectedValue "Automatic and Running" -ActualValue "$startType and $status" -Severity "High" `
                        -Recommendation "Start the $displayName service" `
                        -Reference "CIS 5.2"
                }
                else {
                    Add-CheckResult -Category "Services" -CheckName "$displayName Service" `
                        -Description "Ensures that the $displayName service is enabled and running" `
                        -Result "Fail" -ExpectedValue "Automatic and Running" -ActualValue "$startType and $status" -Severity "High" `
                        -Recommendation "Configure the $displayName service to start automatically and ensure it is running" `
                        -Reference "CIS 5.2"
                }
            }
            else {
                Add-CheckResult -Category "Services" -CheckName "$displayName Service" `
                    -Description "Ensures that the $displayName service is enabled and running" `
                    -Result "Warning" -ExpectedValue "Automatic and Running" -ActualValue "Not Installed" -Severity "High" `
                    -Recommendation "Install the $displayName service or component" `
                    -Reference "CIS 5.2"
            }
        }
    }
    catch {
        Write-Log -Message "Error checking services: $_" -Level "Error"
    }
}

# Function to check network settings
function Test-NetworkSettings {
    Write-Log -Message "Checking network settings..." -Level "Info"
    
    try {
        # Check Network Shares
        $shares = Get-WmiObject -Class Win32_Share | Where-Object { $_.Name -notmatch '^[A-Z]\$|^ADMIN\$|^IPC\$' }
        
        if ($shares.Count -eq 0) {
            Add-CheckResult -Category "Network Settings" -CheckName "Network Shares" `
                -Description "Checks for unnecessary network shares" `
                -Result "Pass" -ExpectedValue "No unnecessary shares" -ActualValue "No unnecessary shares found" -Severity "Medium" `
                -Recommendation "Maintain current network share configuration" `
                -Reference "CIS 9.1.1"
        }
        else {
            $shareList = ($shares | ForEach-Object { $_.Name }) -join ", "
            
            Add-CheckResult -Category "Network Settings" -CheckName "Network Shares" `
                -Description "Checks for unnecessary network shares" `
                -Result "Warning" -ExpectedValue "No unnecessary shares" -ActualValue "Found shares: $shareList" -Severity "Medium" `
                -Recommendation "Review and remove unnecessary network shares" `
                -Reference "CIS 9.1.1"
        }
        
        # Check IPv6 Protocol
        $ipv6Enabled = (Get-NetAdapterBinding | Where-Object { $_.ComponentID -eq 'ms_tcpip6' -and $_.Enabled -eq $true }).Count -gt 0
        
        if ($ipv6Enabled) {
            Add-CheckResult -Category "Network Settings" -CheckName "IPv6 Protocol" `
                -Description "Checks if IPv6 is enabled and properly configured" `
                -Result "Warning" -ExpectedValue "Disabled if not required" -ActualValue "Enabled" -Severity "Low" `
                -Recommendation "If IPv6 is not required, consider disabling it" `
                -Reference "CIS 18.5.19.2.1"
        }
        else {
            Add-CheckResult -Category "Network Settings" -CheckName "IPv6 Protocol" `
                -Description "Checks if IPv6 is enabled and properly configured" `
                -Result "Pass" -ExpectedValue "Disabled if not required" -ActualValue "Disabled" -Severity "Low" `
                -Recommendation "No action required" `
                -Reference "CIS 18.5.19.2.1"
        }
        
        # Check SMB v1 Protocol
        $smbv1Enabled = (Get-SmbServerConfiguration -ErrorAction SilentlyContinue).EnableSMB1Protocol
        
        if ($null -eq $smbv1Enabled) {
            # Try alternative method
            $smbv1Feature = (Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue).State -eq "Enabled"
            
            if ($null -eq $smbv1Feature) {
                # Try registry check as last resort
                $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
                $smbv1Enabled = (Get-ItemProperty -Path $regPath -Name "SMB1" -ErrorAction SilentlyContinue).SMB1 -eq 1
            }
            else {
                $smbv1Enabled = $smbv1Feature
            }
        }
        
        if ($smbv1Enabled) {
            Add-CheckResult -Category "Network Settings" -CheckName "SMB v1 Protocol" `
                -Description "Checks if the SMBv1 protocol is disabled" `
                -Result "Fail" -ExpectedValue "Disabled" -ActualValue "Enabled" -Severity "High" `
                -Recommendation "Disable SMBv1 protocol" `
                -Reference "CIS 18.3.2"
        }
        else {
            Add-CheckResult -Category "Network Settings" -CheckName "SMB v1 Protocol" `
                -Description "Checks if the SMBv1 protocol is disabled" `
                -Result "Pass" -ExpectedValue "Disabled" -ActualValue "Disabled" -Severity "High" `
                -Recommendation "No action required" `
                -Reference "CIS 18.3.2"
        }
        
        # Check NetBIOS over TCP/IP
        $netbiosEnabled = $false
        
        # Get all network adapters
        $adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
        
        foreach ($adapter in $adapters) {
            if ($adapter.TcpipNetbiosOptions -eq 0 -or $adapter.TcpipNetbiosOptions -eq 1) {
                $netbiosEnabled = $true
                break
            }
        }
        
        if ($netbiosEnabled) {
            Add-CheckResult -Category "Network Settings" -CheckName "NetBIOS over TCP/IP" `
                -Description "Checks if NetBIOS over TCP/IP is disabled" `
                -Result "Warning" -ExpectedValue "Disabled" -ActualValue "Enabled" -Severity "Medium" `
                -Recommendation "Disable NetBIOS over TCP/IP on all network adapters" `
                -Reference "CIS 18.5.4.2"
        }
        else {
            Add-CheckResult -Category "Network Settings" -CheckName "NetBIOS over TCP/IP" `
                -Description "Checks if NetBIOS over TCP/IP is disabled" `
                -Result "Pass" -ExpectedValue "Disabled" -ActualValue "Disabled" -Severity "Medium" `
                -Recommendation "No action required" `
                -Reference "CIS 18.5.4.2"
        }
    }
    catch {
        Write-Log -Message "Error checking network settings: $_" -Level "Error"
    }
}

# Function to check advanced settings
function Test-AdvancedSettings {
    Write-Log -Message "Checking advanced settings..." -Level "Info"
    
    try {
        # Check Windows Defender Status
        if ($Results.ComputerInfo.OSVersion -notlike "*Server 2012*") {
            # Get Windows Defender status using PowerShell cmdlets
            $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
            
            # Check if Windows Defender is enabled
            if ($defenderStatus) {
                $realTimeProtection = $defenderStatus.RealTimeProtectionEnabled
                $avSignatureStatus = $defenderStatus.AntivirusSignatureAge
                
                # Check Real-Time Protection
                if ($realTimeProtection) {
                    Add-CheckResult -Category "Advanced Settings" -CheckName "Windows Defender Real-Time Protection" `
                        -Description "Ensures that Windows Defender real-time protection is enabled" `
                        -Result "Pass" -ExpectedValue "Enabled" -ActualValue "Enabled" -Severity "High" `
                        -Recommendation "Maintain Windows Defender real-time protection as enabled" `
                        -Reference "CIS 18.9.76.3.1"
                }
                else {
                    Add-CheckResult -Category "Advanced Settings" -CheckName "Windows Defender Real-Time Protection" `
                        -Description "Ensures that Windows Defender real-time protection is enabled" `
                        -Result "Fail" -ExpectedValue "Enabled" -ActualValue "Disabled" -Severity "High" `
                        -Recommendation "Enable Windows Defender real-time protection" `
                        -Reference "CIS 18.9.76.3.1"
                }
                
                # Check Signature Age
                if ($avSignatureStatus -le 7) {
                    Add-CheckResult -Category "Advanced Settings" -CheckName "Windows Defender Signature Age" `
                        -Description "Ensures that Windows Defender signatures are up to date" `
                        -Result "Pass" -ExpectedValue "Less than 7 days old" -ActualValue "$avSignatureStatus days old" -Severity "High" `
                        -Recommendation "Maintain Windows Defender signature updates" `
                        -Reference "CIS 18.9.76.3.2"
                }
                else {
                    Add-CheckResult -Category "Advanced Settings" -CheckName "Windows Defender Signature Age" `
                        -Description "Ensures that Windows Defender signatures are up to date" `
                        -Result "Fail" -ExpectedValue "Less than 7 days old" -ActualValue "$avSignatureStatus days old" -Severity "High" `
                        -Recommendation "Update Windows Defender signatures" `
                        -Reference "CIS 18.9.76.3.2"
                }
            }
            else {
                # Try a registry-based approach as fallback
                $defenderKey = "HKLM:\SOFTWARE\Microsoft\Windows Defender"
                $defenderEnabled = (Get-ItemProperty -Path $defenderKey -Name "DisableAntiSpyware" -ErrorAction SilentlyContinue).DisableAntiSpyware -ne 1
                
                if ($defenderEnabled) {
                    Add-CheckResult -Category "Advanced Settings" -CheckName "Windows Defender" `
                        -Description "Ensures that Windows Defender is enabled" `
                        -Result "Warning" -ExpectedValue "Enabled with real-time protection" -ActualValue "Appears enabled but status couldn't be determined" -Severity "High" `
                        -Recommendation "Verify Windows Defender configuration" `
                        -Reference "CIS 18.9.76"
                }
                else {
                    Add-CheckResult -Category "Advanced Settings" -CheckName "Windows Defender" `
                        -Description "Ensures that Windows Defender is enabled" `
                        -Result "Fail" -ExpectedValue "Enabled with real-time protection" -ActualValue "Disabled or not installed" -Severity "High" `
                        -Recommendation "Enable Windows Defender" `
                        -Reference "CIS 18.9.76"
                }
            }
        }
        
        # Check BitLocker Status
        try {
            $bitlockerVolumes = Get-BitLockerVolume -ErrorAction Stop
            $osVolume = $bitlockerVolumes | Where-Object { $_.MountPoint -eq $env:SystemDrive }
            
            if ($osVolume) {
                $bitlockerStatus = $osVolume.ProtectionStatus
                
                if ($bitlockerStatus -eq "On") {
                    Add-CheckResult -Category "Advanced Settings" -CheckName "BitLocker Encryption" `
                        -Description "Ensures that the OS drive is encrypted with BitLocker" `
                        -Result "Pass" -ExpectedValue "Enabled" -ActualValue "Enabled" -Severity "High" `
                        -Recommendation "Maintain BitLocker encryption" `
                        -Reference "CIS 18.9.11"
                }
                else {
                    Add-CheckResult -Category "Advanced Settings" -CheckName "BitLocker Encryption" `
                        -Description "Ensures that the OS drive is encrypted with BitLocker" `
                        -Result "Fail" -ExpectedValue "Enabled" -ActualValue "Disabled" -Severity "High" `
                        -Recommendation "Enable BitLocker encryption for the OS drive" `
                        -Reference "CIS 18.9.11"
                }
            }
            else {
                Add-CheckResult -Category "Advanced Settings" -CheckName "BitLocker Encryption" `
                    -Description "Ensures that the OS drive is encrypted with BitLocker" `
                    -Result "Fail" -ExpectedValue "Enabled" -ActualValue "Not configured" -Severity "High" `
                    -Recommendation "Enable BitLocker encryption for the OS drive" `
                    -Reference "CIS 18.9.11"
            }
        }
        catch {
            # Check if BitLocker feature is available
            $tpm = Get-WmiObject -Class Win32_Tpm -Namespace root\CIMV2\Security\MicrosoftTpm -ErrorAction SilentlyContinue
            
            if ($tpm) {
                Add-CheckResult -Category "Advanced Settings" -CheckName "BitLocker Encryption" `
                    -Description "Ensures that the OS drive is encrypted with BitLocker" `
                    -Result "Warning" -ExpectedValue "Enabled" -ActualValue "TPM available but BitLocker status unknown" -Severity "High" `
                    -Recommendation "Verify and enable BitLocker encryption for the OS drive" `
                    -Reference "CIS 18.9.11"
            }
            else {
                Add-CheckResult -Category "Advanced Settings" -CheckName "BitLocker Encryption" `
                    -Description "Ensures that the OS drive is encrypted with BitLocker" `
                    -Result "Warning" -ExpectedValue "Enabled" -ActualValue "TPM not available or BitLocker not supported" -Severity "High" `
                    -Recommendation "Verify hardware compatibility and consider alternative encryption solutions" `
                    -Reference "CIS 18.9.11"
            }
        }
        
        # Check Windows Update Last Success
        $wuKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Detect"
        $lastSuccessTime = Get-ItemProperty -Path $wuKey -Name "LastSuccessTime" -ErrorAction SilentlyContinue
        
        if ($lastSuccessTime) {
            try {
                $lastCheckTime = [DateTime]::Parse($lastSuccessTime.LastSuccessTime)
                $daysSinceLastCheck = ([DateTime]::Now - $lastCheckTime).Days
                
                if ($daysSinceLastCheck -le 7) {
                    Add-CheckResult -Category "Advanced Settings" -CheckName "Windows Update Last Check" `
                        -Description "Ensures that Windows Update has checked for updates recently" `
                        -Result "Pass" -ExpectedValue "Within last 7 days" -ActualValue "$daysSinceLastCheck days ago" -Severity "Medium" `
                        -Recommendation "Maintain regular Windows Update checks" `
                        -Reference "CIS 18.9.85"
                }
                else {
                    Add-CheckResult -Category "Advanced Settings" -CheckName "Windows Update Last Check" `
                        -Description "Ensures that Windows Update has checked for updates recently" `
                        -Result "Fail" -ExpectedValue "Within last 7 days" -ActualValue "$daysSinceLastCheck days ago" -Severity "Medium" `
                        -Recommendation "Check for Windows Updates manually and ensure automatic updates are properly configured" `
                        -Reference "CIS 18.9.85"
                }
            }
            catch {
                Add-CheckResult -Category "Advanced Settings" -CheckName "Windows Update Last Check" `
                    -Description "Ensures that Windows Update has checked for updates recently" `
                    -Result "Warning" -ExpectedValue "Within last 7 days" -ActualValue "Date parsing error: $($lastSuccessTime.LastSuccessTime)" -Severity "Medium" `
                    -Recommendation "Check Windows Update status manually" `
                    -Reference "CIS 18.9.85"
            }
        }
        else {
            Add-CheckResult -Category "Advanced Settings" -CheckName "Windows Update Last Check" `
                -Description "Ensures that Windows Update has checked for updates recently" `
                -Result "Warning" -ExpectedValue "Within last 7 days" -ActualValue "No record found" -Severity "Medium" `
                -Recommendation "Check Windows Update status manually" `
                -Reference "CIS 18.9.85"
        }
    }
    catch {
        Write-Log -Message "Error checking advanced settings: $_" -Level "Error"
    }
}

# Calculate compliance score
function Calculate-ComplianceScore {
    $Results.Summary.ComplianceScore = if ($Results.Summary.TotalChecks -gt 0) {
        [math]::Round(($Results.Summary.PassedChecks / $Results.Summary.TotalChecks) * 100, 2)
    }
    else {
        0
    }
}

# Export results to CSV
function Export-ResultsToCSV {
    param (
        [string]$CSVPath
    )
    
    $allResults = @()
    
    $allResults += $Results.AccountPolicies
    $allResults += $Results.LocalPolicies
    $allResults += $Results.AuditPolicies
    $allResults += $Results.RegistrySettings
    $allResults += $Results.ServicesCheck
    $allResults += $Results.NetworkSettings
    $allResults += $Results.AdvancedSettings
    
    if (-not $IncludeAllResults) {
        $filteredResults = $allResults | Where-Object { $_.Result -ne "Pass" }
    }
    else {
        $filteredResults = $allResults
    }
    
    try {
        $filteredResults | Export-Csv -Path $CSVPath -NoTypeInformation
        Write-Log -Message "Results exported to $CSVPath" -Level "Success"
    }
    catch {
        Write-Log -Message "Error exporting results to CSV: $_" -Level "Error"
    }
}

# Function to display summary results
function Show-Summary {
    Write-Host "`nSecurity Baseline Audit Summary for $($Results.ComputerInfo.ComputerName)" -ForegroundColor Cyan
    Write-Host "===========================================================" -ForegroundColor Cyan
    Write-Host "OS Version: $($Results.ComputerInfo.OSVersion)"
    Write-Host "Scan Time: $($Results.ComputerInfo.ScanTime)"
    Write-Host "===========================================================" -ForegroundColor Cyan
    Write-Host "Total Checks:   $($Results.Summary.TotalChecks)"
    Write-Host "Passed Checks:  $($Results.Summary.PassedChecks)" -ForegroundColor Green
    Write-Host "Failed Checks:  $($Results.Summary.FailedChecks)" -ForegroundColor Red
    Write-Host "Warning Checks: $($Results.Summary.WarningChecks)" -ForegroundColor Yellow
    Write-Host "===========================================================" -ForegroundColor Cyan
    Write-Host "Compliance Score: $($Results.Summary.ComplianceScore)%" -ForegroundColor $(if ($Results.Summary.ComplianceScore -ge 80) { "Green" } elseif ($Results.Summary.ComplianceScore -ge 60) { "Yellow" } else { "Red" })
    Write-Host "===========================================================" -ForegroundColor Cyan
    
    # Display results by category
    $categories = @(
        @{Name = "Account Policies"; Data = $Results.AccountPolicies},
        @{Name = "Local Policies"; Data = $Results.LocalPolicies},
        @{Name = "Audit Policies"; Data = $Results.AuditPolicies},
        @{Name = "Registry Settings"; Data = $Results.RegistrySettings},
        @{Name = "Services"; Data = $Results.ServicesCheck},
        @{Name = "Network Settings"; Data = $Results.NetworkSettings},
        @{Name = "Advanced Settings"; Data = $Results.AdvancedSettings}
    )
    
    foreach ($category in $categories) {
        $failedItems = $category.Data | Where-Object { $_.Result -eq "Fail" }
        $warningItems = $category.Data | Where-Object { $_.Result -eq "Warning" }
        
        if ($failedItems.Count -gt 0 -or $warningItems.Count -gt 0) {
            Write-Host "`n$($category.Name):" -ForegroundColor Cyan
            
            if ($failedItems.Count -gt 0) {
                Write-Host "  Failed Items:" -ForegroundColor Red
                foreach ($item in $failedItems) {
                    Write-Host "    - $($item.CheckName): $($item.ActualValue) (Expected: $($item.ExpectedValue))" -ForegroundColor Red
                }
            }
            
            if ($warningItems.Count -gt 0) {
                Write-Host "  Warning Items:" -ForegroundColor Yellow
                foreach ($item in $warningItems) {
                    Write-Host "    - $($item.CheckName): $($item.ActualValue) (Expected: $($item.ExpectedValue))" -ForegroundColor Yellow
                }
            }
        }
    }
    
    Write-Host "`nDetailed log saved to: $LogFile" -ForegroundColor Cyan
    if ($ExportCSV) {
        Write-Host "Detailed results exported to: $CSVPath" -ForegroundColor Cyan
    }
}

# Main execution
Write-Host "Starting Security Baseline Audit..." -ForegroundColor Cyan
Write-Log -Message "Starting Security Baseline Audit" -Level "Info"

# Begin executing checks
Get-SystemInformation
Test-AccountPolicies
Test-LocalSecurityPolicies
Test-AuditPolicies
Test-RegistrySettings
Test-Services
Test-NetworkSettings
Test-AdvancedSettings

# Calculate compliance score
Calculate-ComplianceScore

# Export results to CSV if enabled
if ($ExportCSV) {
    Export-ResultsToCSV -CSVPath $CSVPath
}

# Display summary results
Show-Summary

Write-Log -Message "Security Baseline Audit completed" -Level "Success"
Write-Host "`nSecurity Baseline Audit completed." -ForegroundColor Green
