# SCRIPT CHECKS FOR EXISTENCE AND VERSION OF THE CONFIGURATION MANAGER CLIENT
# IF THE CLIENT IS INSTALLED AND LESS THAN CURRENT VERSION, IT WILL BE UNINSTALLED, CLEANUP IS PERFORMED, AND THE NEW CLIENT IS INSTALLED
# IF THE CLIENT DOES NOT EXIST, CLEANUP IS PERFORMED AND THE NEW CLIENT IS INSTALLED
# IF THE CLIENT EXISTS AND IS THE CORRECT VERSION, CLEANUP OF REGISTRY KEYS IS PERFORMED, JUST IN CASE

#
# NEW VERSION AS OF 10/25/2018 TO FORCE ALLOWEDMPS VALUE REGARDLESS IF IT EXISTS OR NOT
# 08/11/2021 - Steele - Consolidated all different scripts across bases into one, which relies on a csv to find MPs and MECM site code
#

############################################
# Intialize logging
# Had to move up so we can write a log for found site
############################################
#Logging
$Log = 'C:\SCCM_CB_InstallScript.log'
$LogCheck = Test-Path $Log
If (!$LogCheck){
    New-Item -Path C:\ -ItemType File -Name SCCM_CB_InstallScript.log -ErrorAction SilentlyContinue
}

#Roll log if it is too big
$LogFileLength = (Get-Item C:\SCCM_CB_InstallScript.log).Length
If ($LogFileLength -ge 3010152){
    If (Test-Path "C:\SCCM_CB_InstallScript.lo_"){Remove-Item "C:\SCCM_CB_InstallScript.lo_" -Force}
    Rename-Item $Log "C:\SCCM_CB_InstallScript.lo_" -Force
    New-Item -Path C:\ -ItemType File -Name SCCM_CB_InstallScript.log -ErrorAction SilentlyContinue
}

Function Write-Log{
    Param([string]$logline)
    $logline2 = "$(get-date -format g)     " + "$logline"
    Add-Content $Log -Value $logline2
}
Write-Log "[Script Start warning] PowerShell script for SCCM CB install has started."

############################################
# Determine MPs/Site code based on computer's AD site
############################################
#Get AD site
$ADSite = (nltest /dsgetsite | select -First 1).trim()
Write-Log "$env:computername is reporting to be in AD site $ADSite."

#The location of the GPO to deploy the scheduled task that kicks this script off
$domainFQDN = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().name
$Location = "\\$domainFQDN\NETLOGON\CurrentBranchClient\"

#Import csv with out MPs and MECM site codes
#$SiteToMPs = Import-Csv ([environment]::GetFolderPath("Desktop") + "\SiteToMPs.csv")
$SiteToMPs = "$Location\SiteToMPs.csv"
$item = $SiteToMPs | where SiteName -eq $ADSite

if ($item -ne $null) {
    $MECMSiteCode = $item.MECMSiteCode
    #SCCM CB Management Points - most bases only have one, but some have multiple. 
        #Format for single: $MPs = @("Server1.prod.af.smil.mil")
        #Format for double: $MPs = @("Server1.prod.af.smil.mil","Server2.prod.af.smil.mil")
    [array]$MPs = $item.MPs.Split(",").Split(";")
    }
if ($item -eq $null -or $MECMSiteCode -eq $null -or $MPs.Count -eq 0) {
    Write-Log "$ADSite is not a handled site, script will now exit."
    Exit
    }
    
Write-Log "MECM Site Code : $MECMSiteCode"
Write-Log "Management Point(s) : $($MPs -join ",")"

############################################
# Nothing else to edit below this line
############################################

#Check if computer is a linked clone VM - Script exits if true
$sitecode = Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\SMS\DP" | select -ExpandProperty "sitecode"
$lastinst = Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\CCMsetup" | select -ExpandProperty "LastSuccessfulInstallParams"

Write-Log "Checking if system is in the Linked Clones OU or a Domain Controller"
$filter = "(&(objectcategory=computer)(objectclass=computer)(cn=$env:computername))"
[string]$dn = ([adsisearcher]$filter).findone().properties.distinguishedname
if ($dn -like "*Linked Clones*"){
    Write-Log "System is a linked clone VM. Script will now exit."
    Exit
}
if ($dn -like "*Domain Controllers*"){
    Write-Log "System is a DC. Script will now check site assignment."
    if ($sitecode -eq $MECMSiteCode){
        Write-Log "DC is in $MECMSiteCode. Checking allowedMPs value."
        if (!$(Test-Path 'HKLM:\SOFTWARE\Microsoft\CCM')){
            Write-Log "Creating key for Allowed MPs"
            Try{
                New-ItemProperty -Path HKLM:\Software\Microsoft\CCM -Name AllowedMPs -PropertyType MultiString -Value $MPs -Force -ErrorAction Stop
                }
            Catch{
                Write-Log "There was an error creating the AllowedMPs multistring value"
                }
            Exit
        }
        else {
            Write-Log "Ensuring AllowedMPs registry value is the correct one"
            Try{
                New-ItemProperty -Path HKLM:\Software\Microsoft\CCM -Name AllowedMPs -PropertyType MultiString -Value $MPs -Force -ErrorAction Stop
                Write-Log "The allowedMPs key is present and correct on this DC. The script will now exit"
                }
            Catch{
                Write-Log "There was an error creating the AllowedMPs multistring value"
                }
            Exit
        }
    }
    else {
        Write-Log "System is a DC and is in the $sitecode site. Script will now exit."
        Exit
    }
}
Else {
    Write-Log "System is not a linked clone VM or DC. Continuing..."
}

#Scriptblock to uninstall SCCM
$UninstallSCCM = {
    param ($Log)

    Function Write-Log{
        Param([string]$logline)
        $logline2 = "$(get-date -format g)     " + "$logline"
        Add-Content $Log -Value $logline2
    }

    Write-Log "####Begin UninstallSCCM Scriptblock####"
    Write-Log "Uninstalling SCCM client. Reference C:\Windows\ccmsetup\Logs\ccmsetup.log for more details"
    Start-Process C:\Windows\Temp\CB_Migration\CB_Client\ccmsetup.exe /uninstall -Wait
    $UninstallSucceeded = 0
    $Complete = Get-Date
    Do {
        $LogTail = Get-Content C:\Windows\ccmsetup\Logs\ccmsetup.log | select -last 20
        [array]$UninstallSucceeded = ($LogTail | Select-String 'CcmSetup is exiting with return code 0').count
        Write-Log "Sleeping for 15 second while waiting for `"Uninstall Succeeded.`" message in ccmsetup.log"
        Start-Sleep -Seconds 15
        If ($(New-Timespan $Complete $(Get-Date)).TotalMinutes -ge 10){
            Write-Log "Error: Waiting period has timed out, ccmsetup is taking too long. Something must be wrong. Script will now exit."
            Exit
        }
    } Until (($UninstallSucceeded -gt 0))
    Write-Log "Client has been removed"
    Write-Log "####End of UninstallSCCM Scriptblock####"
}

#Check if computer is a already on Prod SCCM CB and healthy - Ensures allowedMPs is correct and exits if true
Write-Log "Checking site assignment and client health."


If (($sitecode -eq $MECMSiteCode) -and ($lastinst -match "ACCROOT")){
    Write-Log "SCCM Client is corrupted by legacy client push event. Begin uninstall scriptblock."
    Invoke-Command $UninstallSCCM -ArgumentList $Log
    }
elseif ($lastinst -match ".prod."){ 
    Write-Log "SCCM Client is already on the $MECMSiteCode site and not corrupt. The script will now check for allowedMPs key."
    if (!$(Test-Path 'HKLM:\SOFTWARE\Microsoft\CCM')){
        Write-Log "Creating key for Allowed MPs"
        Try{
            New-ItemProperty -Path HKLM:\Software\Microsoft\CCM -Name AllowedMPs -PropertyType MultiString -Value $MPs -Force -ErrorAction Stop
            }
        Catch{
            Write-Log "There was an error creating the AllowedMPs multistring value"
            }
        Exit
    }
    else {
        Write-Log "Ensuring AllowedMPs registry value is the correct one"
        Try{
            New-ItemProperty -Path HKLM:\Software\Microsoft\CCM -Name AllowedMPs -PropertyType MultiString -Value $MPs -Force -ErrorAction Stop
            Write-Log "allowedMPs key is present and correct."
            }
        Catch{
            Write-Log "There was an error creating the AllowedMPs multistring value"
            }
        Exit
    }
}
Else {
    Write-Log "SCCM Client is not on the $MECMSiteCode site. Continuing..."
}


#1802 client version
$CurrentClientVer = '5.00.8634.0'

#CCMSETUP
$CCMSetupEXE = 'C:\Windows\Temp\CB_Migration\CB_Client\ccmsetup.exe'
$CCMSetupArgs = "/mp:$($MPs[0]) /skipprereq:silverlight.exe SMSSITECODE=$MECMSiteCode SMSMP=$($MPs[0])"


Set-Location $Location

Write-Log "[Variables] Location to run this script from will be $Location"
Write-Log "[Variables] MP(s) specified are $($MPs -join ',')"
Write-Log "[Variables] Target client version for this script is $CurrentClientVer"
Write-Log "[Variables] CCMSetup install command will be $CCMSetupEXE $CCMSetupArgs"

Write-Log "Copying files to C:\Windows\TEMP\CB_Migration"
ROBOCOPY .\CB_Migration C:\Windows\Temp\CB_Migration /MIR
Write-Log "File copy finished with ROBOCOPY"

#Function to check if a reboot is pending
Function Test-PendingReboot{
    If (Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending' -ErrorAction Ignore){
        Return $true
    }
    If (Get-Item 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired' -ErrorAction Ignore){
        Return $true
    }
    If (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction Ignore){
        Return $true
    }
    Try{
        $CCMUtil = [wmiclass]"\\.\root\ccm\clientsdk:CCM_ClientUtilities"
        $Status = $CCMUtil.DetermineIfRebootPending()
        If (($Status -ne $null) -and $Status.RebootPending){
            Return $true
        }
    } Catch{}

    Return $false
}

#Function to clean old SCCM files
Function Clean-OldSCCM{
    Write-Log "####Begin Clean-OldSCCM Function####"

    #REMOVE OLD CLIENT CERTS
    Write-Log "Checking for SMS Client Certificates"
    $Certs = Get-ChildItem Cert:\LocalMachine\SMS
    $CertsExist = $Certs -ne $null;
    IF($CertsExist){
        $certs | remove-item -Force
        Write-Log "SMS Client Certificates deleted"
        } Else{
        Write-Log "No SMS Client Certificates found"
        }
    
    $ThingsToDelete = @('C:\Windows\SysWOW64\CCM',
                        'C:\Windows\System32\CCM',
                        'C:\Windows\SMSCFG.ini',
                        'C:\Windows\ccmsetup',
                        'C:\Windows\CCM',
                        'C:\Windows\SMSAdvancedClient.sccm2007ac_sp2_kb3044077_x86_enu.mif',
                        'HKLM:\SOFTWARE\Microsoft\CCMSetup',
                        'HKLM:\SOFTWARE\Microsoft\CCM',
                        'HKLM:\SOFTWARE\Microsoft\SMS',
                        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\CCMSetup',
                        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\CCM',
                        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\SMS')

    ForEach ($Thing in $ThingsToDelete){
        Write-Log "Checking existence of $Thing."
        If (Test-Path $Thing){
            Write-Log "Found $Thing"
            Try{Remove-Item $Thing -Recurse -Force -ErrorAction Stop}
                Catch{Write-Log "There was an error deleting $Thing"}
            If (!$(Test-Path $Thing)){Write-Log "$Thing has been deleted"}
        }
    }


    Write-Log "####End Clean-OldSCCM Function####"
#END Function
}

#Function to remove sccm 2007 remnants
Function Remove-2007Remnants(){
    Write-Log "####Begin Remove-2007Remnants Function####"

    $ThingsToDelete = @('C:\Windows\SysWOW64\CCM',
                        'C:\Windows\System32\CCM')
    ForEach ($Thing in $ThingsToDelete){
        Write-Log "Checking for existence of $Thing."
        If (Test-Path $Thing){
            Write-Log "Found $Thing"
            Try{ Remove-Item $Thing -Recurse -Force -ErrorAction Stop }
                Catch{ Write-Log "There was an error deleting $Thing" }
            If (!$(Test-Path $Thing)){ Write-Log "$Thing has been deleted" }
        }
    }
    Write-Log "Deleting 2007 Registry Keys for site assignement and installation parameters"
    Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\SMS\Mobile Client' -Name 'GPRequestedSiteAssignmentCode' -Force -EA 0
    Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\SMS\Mobile Client' -Name 'GPSiteAssignmentRetryInterval(Min)' -Force -EA 0
    Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\SMS\Mobile Client' -Name 'GPSiteAssignmentRetryDuration(Hour)' -Force -EA 0
    Remove-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\SMS\Mobile Client' -Name 'GPRequestedSiteAssignmentCode' -Force -EA 0
    Remove-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\SMS\Mobile Client' -Name 'GPSiteAssignmentRetryInterval(Min)' -Force -EA 0
    Remove-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\SMS\Mobile Client' -Name 'GPSiteAssignmentRetryDuration(Hour)' -Force -EA 0
    Remove-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\ccmsetup' -Recurse -Force -EA 0
    Remove-Item -Path 'HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\ccmsetup' -Recurse -Force -EA 0
    Write-Log "####End Remove-2007Remnants Function####"
#END Function
}



#Scriptblock to install SCCM
$InstallSCCM = {
    param ($CCMSetupEXE,$CCMSetupArgs,$MPs,$Log)
    
    Function Write-Log{
        Param([string]$logline)
        $logline2 = "$(get-date -format g)     " + "$logline"
        Add-Content $Log -Value $logline2
    }
    Write-Log "####Begin InstallSCCM Scriptblock####"
    Write-Log "Beginning Installation of Current Branch Client, refer to C:\Windows\CCMSetup\logs\ccmsetup.log"
    Start-Process $CCMSetupEXE $CCMSetupArgs -Wait
    $Complete = Get-Date
    Do {
        Write-Log "Sleeping for 15 seconds while waiting for HKLM:\SOFTWARE\Microsoft\CCM to be created"
        Start-Sleep -Seconds 15
        If ($(New-Timespan $Complete $(Get-Date)).TotalMinutes -ge 10){
            Write-Log "Error: Waiting period has timed out, ccmsetup is taking too long. Something must be wrong. Script will now exit."
            Exit
        }
    } While (!$(Test-Path 'HKLM:\SOFTWARE\Microsoft\CCM'))
    Write-Log "Creating key for Allowed MPs"
    Try{New-ItemProperty -Path HKLM:\Software\Microsoft\CCM -Name AllowedMPs -PropertyType MultiString -Value $MPs -Force -ErrorAction Stop}
        Catch{Write-Log "There was an error creating the AllowedMPs multistring value"}

    $Install0 = 0
    $Install7 = 0
    $Complete = Get-date
    Do {
        $LogTail = Get-Content C:\Windows\ccmsetup\Logs\ccmsetup.log | select -last 20
        $Install0 = ($LogTail | Select-String 'CcmSetup is exiting with return code 0').count
        $Install7 = ($LogTail | Select-String 'CcmSetup is exiting with return code 7').count
        Write-Log "Sleeping for 15 seconds while waiting for exit code 0 or 7 to appear in ccmsetup.log"
        Start-Sleep -Seconds 15
        If ($(New-Timespan $Complete $(Get-Date)).TotalMinutes -ge 10){
            Write-Log "Error: Waiting period has timed out, ccmsetup is taking too long. Something must be wrong. Script will now exit."
            Exit
        }
    } Until (($Install0 -gt 0) -or ($Install7 -gt 0))

    Write-Log "Finished installing SCCM CB client"
    Write-Log "####End InstallSCCM Scriptblock####"
#END SCRIPTBLOCK
}

#BEGIN MIGRATION
Write-Log "Starting Configuration Manager Migration Check"

#If a reboot is pending, exit the script
Write-Log "Checking if a reboot is pending."
If (Test-PendingReboot){
    Write-Log "Error: A reboot is pending on this machine. Script cannot continue and will now exit."
    EXIT
} Else{Write-Log "No reboot is pending on this system, it is safe to continue."}

$CheckCCMSetupVersion = $false

#Check to see if ccmsetup process is running
Write-Log "Checking for ccmsetup process running on the system."
If (Get-Process -Name ccmsetup){
    Write-Log "ERROR: Ccmsetup process is found running on the system."
    $CheckCCMSetupVersion = $true
} Else{
    Write-Log "Ccmsetup process not found running on the system."
}

#If ccmsetup service exists
Write-Log "Checking for existence of ccmsetup service on the system."
If (Get-Service -Name ccmsetup){
    Write-Log "ERROR: Ccmsetup service is found on the system."
    $CheckCCMSetupVersion = $true
} Else{
    Write-Log "Ccmsetup service not found on the system. It is safe to assume there is no existing installation."
}

#ccmsetup process or service found running on system, see if it is ours
If ($CheckCCMSetupVersion){
    Write-Log "CCMSetup process found running or CCMSetup service exists on this system...checking if it is ours"
    $CCMSetupVersion = (Get-Item -Path C:\Windows\ccmsetup\ccmsetup.exe).VersionInfo | % {('{0}.{1}.{2}.{3}' -f $_.FileMajorPart,$_.FileMinorPart,$_.FileBuildPart,$_.FilePrivatePart)}
    $WantedCCMSetupVersion = (Get-Item -Path C:\Windows\Temp\CB_Migration\CB_Client\ccmsetup.exe).VersionInfo | % {('{0}.{1}.{2}.{3}' -f $_.FileMajorPart,$_.FileMinorPart,$_.FileBuildPart,$_.FilePrivatePart)}
    If ($CCMSetupVersion -lt $WantedCCMSetupVersion){
        Write-Log "CCMSetup process or service running does not look like our version, will attempt removal now"
        Invoke-Command $UninstallSCCM -ArgumentList $Log
    }
}

#CHECK CLIENT FOR APPLICABILITY
Write-Log "Checking presence of SCCM client"

#CHECK FOR PRESENCE OF CLIENT
$ClientService = Get-WmiObject Win32_service | where {$_.Name -eq 'ccmexec'};
$ClientExists = $ClientService -ne $null;
    
IF($ClientExists -eq $true){
    #CLIENT EXISTS, CHECK VERSION
    Write-Log "Client exists, checking version"
    $ClientVer = Get-WmiObject -Namespace root\ccm sms_client | select -ExpandProperty ClientVersion

    #IF CLIENT VERSION IS LESS THAN current CB version or in wrong site, UNINSTALL THE CLIENT
    IF(($Clientver -lt $CurrentClientVer) -or ($lastinst -notmatch ".prod.")){
        Write-Log "Client version is $Clientver and site is $sitecode, calling UninstallSCCM ScriptBlock"
        Invoke-Command -ScriptBlock $UninstallSCCM -ArgumentList $Log
        Write-Log "Checking if ccmsetup.log mentioned a pending reboot"
        $LogTail = Get-Content C:\Windows\ccmsetup\Logs\ccmsetup.log | select -last 20
        $RequestedReboot = ($LogTail | Select-String 'Installation succeeded. Windows Installer has requested a reboot.').count
        If ($RequestedReboot -gt 0){
            Write-Log "Error: ccmsetup.log has requested a reboot. Script cannot continue until after a reboot has been performed. Script will now exit."
            Exit
        }
        Write-Log "Cleaning up old client registry keys, certificates, and directories"
        Clean-OldSCCM
        Remove-2007Remnants
        Write-Log "####Calling InstallSCCM scriptblock####"
        Invoke-Command -ScriptBlock $InstallSCCM -ArgumentList $CCMSetupEXE,$CCMSetupArgs,$MPs,$Log
        Write-Log "####Back to main script####"
    }
        ELSE{
            #CLIENT VERSION IS GOOD
            Write-Log "Client version is $ClientVer and site is $sitecode."
            Write-Log "Client is already up to date and in correct site, no installation necessary. Ensuring 2007 client registry settings are gone."
            Remove-2007Remnants
            Write-Log "Ensuring AllowedMPs registry value is the correct one"
            Try{
                New-ItemProperty -Path HKLM:\Software\Microsoft\CCM -Name AllowedMPs -PropertyType MultiString -Value $MPs -Force -ErrorAction Stop
            }Catch{
                Write-Log "There was an error creating the AllowedMPs multistring value"
            }
        }
    }
    ELSE{
        #NO CLIENT IS INSTALLED, PERFORM CLEANUP AND INSTALL CURRENT CB CLIENT
        Write-Log "No client was detected, performing cleanup of any old client remnants"
        Clean-OldSCCM
        Remove-2007Remnants
        Write-Log "####Calling InstallSCCM scriptblock####"
        Invoke-Command -ScriptBlock $InstallSCCM -ArgumentList $CCMSetupEXE,$CCMSetupArgs,$MPs,$Log
        Write-Log "####Exiting InstallSCCM scriptblock####"
        }
 
Write-Log "SCCM CB Install Script complete."
