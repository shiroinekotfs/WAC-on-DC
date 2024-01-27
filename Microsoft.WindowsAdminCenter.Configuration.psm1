Set-Variable -Name ConstNetShCommand -Option Constant -Value "netsh.exe"
Set-Variable -Name ConstWevutilCommand -Option Constant -Value "wevtutil.exe"
Set-Variable -Name ConstServiceController -Option Constant -Value "sc.exe"
Set-Variable -Name ConstServiceName -Option Constant -Value "WindowsAdminCenter"
Set-Variable -Name ConstAccountManagementServiceName -Option Constant -Value "WindowsAdminCenterAccountManagement"
Set-Variable -Name ConstUpdaterScheduledTaskName -Option Constant -Value "WindowsAdminCenterUpdater"
Set-Variable -Name ConstLauncherName -Option Constant -Value "WindowsAdminCenterLauncher"
Set-Variable -Name ConstEventLogName -Option Constant -Value "WindowsAdminCenter"
Set-Variable -Name ConstDisplayName -Option Constant -Value "Windows Admin Center"
Set-Variable -Name ConstAccountManagementServiceDisplayName -Option Constant -Value "Windows Admin Center Account Management"
Set-Variable -Name ConstUpdaterServiceDisplayName -Option Constant -Value "Windows Admin Center Updater"
Set-Variable -Name ConstServiceDescription -Option Constant -Value "Manage remote Windows computers from web service."
Set-Variable -Name ConstAccountManagementServiceDescription -Option Constant -Value "Manage AAD token and account for Windows Admin Center."
Set-Variable -Name ConstUpdaterServiceDescription -Option Constant -Value "Install updates for Windows Admin Center."
Set-Variable -Name ConstExecutableName -Option Constant -Value "WindowsAdminCenter.exe"
Set-Variable -Name ConstLauncherExecutableName -Option Constant -Value "WindowsAdminCenterLauncher.exe"
Set-Variable -Name ConstAccoutManagementExecutableName -Option Constant -Value "WindowsAdminCenterAccountManagement.exe"
Set-Variable -Name ConstUpdaterExecutableName -Option Constant -Value "WindowsAdminCenterUpdater.exe"
Set-Variable -Name ConstAppConfigJsonName -Option Constant -Value "appsettings.json"
Set-Variable -Name ConstTokenAuthenticationModeTag -Option Constant -Value """TokenAuthenticationMode"":"
Set-Variable -Name ConstSubjectTag -Option Constant -Value """Subject"":" 
Set-Variable -Name ConstProgramDataFolderPath -Option Constant -Value "${env:ProgramData}\WindowsAdminCenter"
Set-Variable -Name ConstServiceFolderPath -Option Constant -Value "${env:ProgramFiles}\WindowsAdminCenter\Service"
Set-Variable -Name ConstUpdaterFolderPath -Option Constant -Value "${env:ProgramData}\WindowsAdminCenter\Updater"
Set-Variable -Name ConstAppId -Option Constant -Value "{13EF9EED-B613-4D2D-8B82-7E5B90BE4990}"
Set-Variable -Name ConstDefaultPort -Option Constant -Value "6600"
Set-Variable -Name ConstUsersSecurityDescriptor -Option Constant -Value "D:(A;;GX;;;AU)(A;;GX;;;NS)"
Set-Variable -Name ConstNetworkServiceSecurityDescriptor -Option Constant -Value "D:(A;;GX;;;NS)"
Set-Variable -Name ConstCertificateKeySecurityDescriptor -Option Constant -Value "O:SYG:SYD:AI(A;;GAGR;;;SY)(A;;GAGR;;;NS)(A;;GAGR;;;BA)(A;;GR;;;BU)"
Set-Variable -Name ConstAccountManagementSecurityDescriptor -Option Constant -Value "D:(A;;CCLCSWRPWPLO;;;NS)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)"
Set-Variable -Name ConstUpdaterScheduledTaskSecurityDescriptor -Option Constant -Value "O:BAD:AI(A;;FR;;;SY)(A;;0x1200a9;;;NS)(A;ID;0x1f019f;;;BA)(A;ID;0x1f019f;;;SY)(A;ID;FA;;;BA)"
Set-Variable -Name ConstSSLCertificateSubjectName -Option Constant -Value "WindowsAdminCenterSelfSigned"
Set-Variable -Name ConstTestSSLCertificateSubjectName -Option Constant -Value "WindowsAdminCenterTestSelfSigned"
Set-Variable -Name ConstSSLCertificateSubjectCN -Option Constant -Value "CN=WindowsAdminCenterSelfSigned"
Set-Variable -Name ConstTestSSLCertificateSubjectCN -Option Constant -Value "CN=WindowsAdminCenterTestSelfSigned"
Set-Variable -Name ConstRootCACertificateSubjectName -Option Constant -Value "WindowsAdminCenterSelfSignedRootCA"
Set-Variable -Name ConstTestRootCACertificateSubjectName -Option Constant -Value "WindowsAdminCenterTestSelfSignedRootCA"
Set-Variable -Name ConstRootCACertificateSubjectCN -Option Constant -Value "CN=WindowsAdminCenterSelfSignedRootCA"
Set-Variable -Name ConstTestRootCACertificateSubjectCN -Option Constant -Value "CN=WindowsAdminCenterTestSelfSignedRootCA"
Set-Variable -Name ConstInboundOpenException -Option Constant -Value "WacInboundOpenException";
Set-Variable -Name ConstCredSspName -Option Constant -Value "Microsoft.WindowsAdminCenter.Credssp"
Set-Variable -Name ConstCredSspGroupName -Option Constant -Value "Windows Admin Center CredSSP"
Set-Variable -Name ConstCredSspGroupDescription -Option Constant -Value "Members of CredSSP operations"
Set-Variable -Name ConstCredSspRoleName -Option Constant -Value "MS-CredSSP-Admin"
Set-Variable -Name ConstShellModuleName -Option Constant -Value "Microsoft.SME.Shell"
Set-Variable -Name ConstRoleCapabilitiesName -Option Constant -Value "Microsoft.WindowsAdminCenter.CredSspPolicy"
Set-Variable -Name ConstCredSspAdmin -Option Constant -Value "MS-CredSSP-Admin"
Set-Variable -Name ConstPolicyFolderPath -Option Constant -Value "${env:ProgramFiles}\WindowsPowerShell\Modules\Microsoft.WindowsAdminCenter.CredSspPolicy"
Set-Variable -Name ConstShellModuleFolderPath -Option Constant -Value "${env:ProgramData}\WindowsAdminCenter\Ux\powershell-module"
Set-Variable -Name ConstCredSspFolderPath -Option Constant -Value "${env:ProgramData}\WindowsAdminCenter\CredSSP"
Set-Variable -Name ConstExtensionsFolderPath -Option Constant -Value "${env:ProgramData}\WindowsAdminCenter\Extensions"
Set-Variable -Name ConstPluginsFolderPath -Option Constant -Value "${env:ProgramData}\WindowsAdminCenter\Plugins"
Set-Variable -Name ConstUxFolderPath -Option Constant -Value "${env:ProgramData}\WindowsAdminCenter\Ux"
Set-Variable -Name ConstModulesFolderPath -Option Constant -Value "${env:ProgramData}\WindowsAdminCenter\Ux\modules"
Set-Variable -Name ConstExtensionsConfigFileName -Option Constant -Value "extensions.config"
Set-Variable -Name ConstExtensionManifestFileName -Option Constant -Value "manifest.json"
Set-Variable -Name ConstExtensionSettingsFileName -Option Constant -Value "settings.json"
Set-Variable -Name ConstExtensionUxFolderName -Option Constant -Value "Ux"
Set-Variable -Name ConstExtensionGatewayFolderName -Option Constant -Value "gateway"
Set-Variable -Name ConstExtensionCatalogsFolderName -Option Constant -Value "Catalogs"
Set-Variable -Name ConstExtensionPackagesFolderName -Option Constant -Value "Packages"
Set-Variable -Name ConstExtensionIndexFileName -Option Constant -Value "index.html"
Set-Variable -Name ConstRoleCapabilities -Option Constant -Value "RoleCapabilities"
Set-Variable -Name ConstWinRmCommand -Option Constant -Value "winrm.cmd"
Set-Variable -Name ConstLogFolderPath -Option Constant -Value "${env:ProgramData}\WindowsAdminCenter\Logs"
Set-Variable -Name ConstLogFileName -Option Constant -Value "Configuration.log"
Set-Variable -Name ConstEntityFrameworkBundleFileName -Option Constant -Value "efbundle.exe"
Set-Variable -Name ConstCoreDllFileName -Option Constant -Value "Microsoft.WindowsAdminCenter.Core.dll"
Set-Variable -Name ConstMachineKeyRootPath -Option Constant -Value "${env:ProgramData}\Microsoft\Crypto\RSA\MachineKeys"
Set-Variable -Name ConstSystemObject -Option Constant -Value "SYSTEM"
Set-Variable -Name ConstNetworkServiceSid -Option Constant -Value "S-1-5-20"
Set-Variable -Name ConstFullControlPermissions -Option Constant -Value "FullControl"
Set-Variable -Name ConstNuGetVersioningDllName -Option Constant -Value "NuGet.Versioning.dll"

#Requires -RunAsAdministrator

enum ExtensionStatus {
    None = 0
    Available = 1
    Installed = 2
    InstallPending = 3
    UnInstallPending = 4
    UpdatePending = 5
}

<#
.SYNOPSIS
    Imports the build signer certificate.

.DESCRIPTION
    Imports the build signer certificate to the TrustedPublisher store.

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, otherwise error.

.EXAMPLE
    Import-WACBuildSignerCertificate
#>
function Import-WACBuildSignerCertificate {
    Param(
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    SetExitWithErrorCode $ExitWithErrorCode

    try {
        $moduleFiles = Get-ChildItem -Path "$PSScriptRoot\..\.." -Include @('*.psm1', '*.psd1') -Recurse
        $importedThumbprints = @{}
        foreach ($moduleFile in $moduleFiles) {
            $moduleAuthenticodeSignature = Get-AuthenticodeSignature -FilePath $moduleFile.FullName
            if ($moduleAuthenticodeSignature.Status -ne "Valid") {
                continue
            }

            if (-not $importedThumbprints.Contains($moduleAuthenticodeSignature.SignerCertificate.Thumbprint) -and
                -not (Test-Path -Path (Join-Path -Path 'Cert:\LocalMachine\TrustedPublisher' -ChildPath $moduleAuthenticodeSignature.SignerCertificate.Thumbprint))) {
                $store = New-Object System.Security.Cryptography.X509Certificates.X509Store -ArgumentList ([System.Security.Cryptography.X509Certificates.StoreName]::TrustedPublisher),
                    ([System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
                $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite -bor [System.Security.Cryptography.X509Certificates.OpenFlags]::MaxAllowed)
                $store.Add($moduleAuthenticodeSignature.SignerCertificate)
                $store.Close()
            }
        }

        if ($importedThumbprints.Count -gt 0) {
            Write-Log -Level INFO -ExitCode 0 -Message "Import-WACBuildSignerCertificate: Successfully imported the build signer certificate(s)."
        }
        else {
            Write-Log -Level WARN -ExitCode 0 -Message "Import-WACBuildSignerCertificate: The configuration modules are not signed, cannot import the build signer certificate(s)."
        }
        ExitWithErrorCode 0
    }
    catch {
        Write-Log -Level WARN -ExitCode 1 -Message "Import-WACBuildSignerCertificate: Failed to import the build signer certificate(s). Error: $_"
        ExitWithErrorCode 1
        throw
    }
    finally {
        if ($null -ne $chain) {
            $chain.Dispose()
            $chain = $null
        }

        if ($null -ne $store) {
            $store.Dispose()
            $store = $null
        }
    }
}

<#
.SYNOPSIS
    Registers the Windows Admin Center service.

.DESCRIPTION
    Registers the Windows Admin Center service. Unregisters the service first if it is already registered.

.PARAMETER Automatic
    Automatically start the service.

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, otherwise error.

.EXAMPLE
    Register-WACService

.EXAMPLE
    Register-WACService -Automatic
#>
function Register-WACService {
    Param(
        [Parameter(Mandatory = $false)]
        [switch]$Automatic,
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    SetExitWithErrorCode $ExitWithErrorCode

    $service = Get-Service -Name $ConstServiceName -ErrorAction SilentlyContinue
    if ($service.Length -gt 0) {
        Unregister-WACService -ExitWithErrorCode:$false
    }

    $basePath = $ConstServiceFolderPath;
    $path = Join-Path -Path $basePath -ChildPath $ConstExecutableName
    $path = [System.IO.Path]::GetFullPath($path)

    $networkServiceSid = New-Object System.Security.Principal.SecurityIdentifier -ArgumentList $ConstNetworkServiceSid
    $networkServiceName = $networkServiceSid.Translate([System.Security.Principal.NTAccount]).Value
    $startMode = if ($Automatic) { "auto" } else { "demand" }
    Invoke-WACWinCommand -Command $ConstServiceController -Parameters "create", $ConstServiceName, "type=", "own", "start=", $startMode, "depend=", "winrm", "obj=", """$networkServiceName""", "binpath=", """$path""", "displayname=", """$ConstDisplayName"""
    Invoke-WACWinCommand -Command $ConstServiceController -Parameters "description", $ConstServiceName, """$ConstServiceDescription"""
    
    Write-Log -Level INFO -ExitCode 0 -Message "Register-WACService: Successfully registered Windows Admin Center service."
    ExitWithErrorCode 0
}

<#
.SYNOPSIS
    Registers the Windows Admin Center Account Management service.

.DESCRIPTION
    Registers the Windows Admin Center Account Management service. Unregisters the service first if it is already registered.

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, otherwise error.

.EXAMPLE
    Register-WACAccountManagementService
#>
function Register-WACAccountManagementService {
    Param(
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    SetExitWithErrorCode $ExitWithErrorCode

    $service = Get-Service -Name $ConstAccountManagementServiceName -ErrorAction SilentlyContinue
    if ($service.Length -gt 0) {
        Unregister-WACAccountManagementService -ExitWithErrorCode:$false
    }

    $path = Join-Path -Path $ConstServiceFolderPath -ChildPath $ConstAccoutManagementExecutableName
    $path = [System.IO.Path]::GetFullPath($path)

    Invoke-WACWinCommand -Command $ConstServiceController -Parameters "create", $ConstAccountManagementServiceName, "type=", "own", "start=", "demand", "binpath=", """$path""", "displayname=", """$ConstAccountManagementServiceDisplayName"""
    Invoke-WACWinCommand -Command $ConstServiceController -Parameters "description", $ConstAccountManagementServiceName, """$ConstAccountManagementServiceDescription"""
    Invoke-WACWinCommand -Command $ConstServiceController -Parameters "sdset", $ConstAccountManagementServiceName, $ConstAccountManagementSecurityDescriptor

    Write-Log -Level INFO -ExitCode 0 -Message "Register-WACAccountManagementService: Successfully registered Windows Admin Center Account Management service."
    ExitWithErrorCode 0
}

<#
.SYNOPSIS
    Registers the Windows Admin Center Updater scheduled task.

.DESCRIPTION
    Registers the Windows Admin Center Updater scheduled task. Returns early if the scheduled task is already registered unless Force flag is set.

.PARAMETER Force
    Force the registration of the service.

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, otherwise error.

.EXAMPLE
    Register-WACUpdaterScheduledTask

.EXAMPLE
    Register-WACUpdaterScheduledTask -Force
#>
function Register-WACUpdaterScheduledTask {
    Param(
        [Parameter(Mandatory = $false)]
        [switch]$Force,
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    SetExitWithErrorCode $ExitWithErrorCode

    $service = Get-ScheduledTask -TaskName $ConstUpdaterScheduledTaskName -ErrorAction SilentlyContinue
    if ($service.Length -gt 0) {
        if ($Force -eq $false) {
            Write-Log -Level INFO -ExitCode 0 -Message "Register-WACUpdaterScheduledTask: Windows Admin Center Updater scheduled task is already registered, returning early."
            ExitWithErrorCode 0
            return
        }

        Unregister-WACUpdaterScheduledTask -ExitWithErrorCode:$false
    }

    $path = Join-Path -Path $ConstUpdaterFolderPath -ChildPath $ConstUpdaterExecutableName
    $path = [System.IO.Path]::GetFullPath($path)

    try {
        $action = New-ScheduledTaskAction -Execute $path
        Register-ScheduledTask -TaskName $ConstUpdaterScheduledTaskName -Action $action -User $ConstSystemObject -RunLevel Highest -Force

        $scheduler = New-Object -ComObject Schedule.Service
        $scheduler.Connect()
        $task = $scheduler.GetFolder("\").GetTask($ConstUpdaterScheduledTaskName)
        $task.SetSecurityDescriptor($ConstUpdaterScheduledTaskSecurityDescriptor, 0)
    }
    catch {
        Write-Log -Level ERROR -ExitCode 1 -Message "Register-WACUpdaterScheduledTask: Failed to register Windows Admin Center Updater scheduled task."
        Write-Error $_
        ExitWithErrorCode 1
        throw
    }

    Write-Log -Level INFO -ExitCode 0 -Message "Register-WACUpdaterScheduledTask: Successfully registered Windows Admin Center Updater scheduled task."
    ExitWithErrorCode 0
}

<#
.SYNOPSIS
    Restarts the Windows Admin Center service.

.DESCRIPTION
    Restarts the Windows Admin Center service.

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, otherwise error.

.EXAMPLE
    Restart-WACService
#>
function Restart-WACService {
    Param(
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    SetExitWithErrorCode $ExitWithErrorCode
    try {
        Restart-Service -Name $ConstServiceName -ErrorAction Stop
        Write-Log -Level INFO -ExitCode 0 -Message "Restart-WACService: Successfully restarted Windows Admin Center service."
        ExitWithErrorCode 0
    }
    catch {
        Write-Error $_
        Write-Log -Level ERROR -ExitCode 1 -Message "Restart-WACService: Failed to restart Windows Admin Center service. Error: $_"
        ExitWithErrorCode 1
        throw
    }
}

<#
.SYNOPSIS
    Restarts the Windows Admin Center Account Management service.

.DESCRIPTION
    Restarts the Windows Admin Center Account Management service.

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, otherwise error.

.EXAMPLE
    Restart-WACAccountManagementService
#>
function Restart-WACAccountManagementService {
    Param(
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    SetExitWithErrorCode $ExitWithErrorCode
    try {
        Restart-Service -Name $ConstAccountManagementServiceName -ErrorAction Stop
        Write-Log -Level INFO -ExitCode 0 -Message "Restart-WACAccountManagementService: Successfully restarted Windows Admin Center Account Management service."
        ExitWithErrorCode 0
    }
    catch {
        Write-Error $_
        Write-Log -Level ERROR -ExitCode 1 -Message "Restart-WACService: Failed to restart Windows Admin Center Account Management service. Error: $_"
        ExitWithErrorCode 1
        throw
    }
}

<#
.SYNOPSIS
    Sets Network Service account access.

.DESCRIPTION
    Sets Network Service account access to Full on %ProgramData%\WindowsAdminCenter folder and %ProgramFiles%\WindowsAdminCenter\Service\appsettings.json with inherited state.

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, otherwise error.

.EXAMPLE
    Set-WACNetworkServiceAccess
#>
function Set-WACNetworkServiceAccess {
    Param(
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    SetExitWithErrorCode $ExitWithErrorCode
    try {
        $networkServiceSid = New-Object System.Security.Principal.SecurityIdentifier -ArgumentList $ConstNetworkServiceSid
        $acl = Get-Acl -Path $ConstProgramDataFolderPath
        $networkService = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $networkServiceSid,$ConstFullControlPermissions,3,"None","Allow"
        $acl.SetAccessRule($networkService)
        Set-Acl -Path $ConstProgramDataFolderPath -AclObject $acl

        $appSettingsPath = GetAppSettingsPath
        $acl = Get-Acl -Path $appSettingsPath
        $appSettings = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $networkServiceSid,$ConstFullControlPermissions,"Allow"
        $acl.SetAccessRule($appSettings)
        Set-Acl -Path $appSettingsPath -AclObject $acl

        Write-Log -Level INFO -ExitCode 0 -Message "Set-WACNetworkServiceAccess: Configured access for Network Service to the data folder and the configuration file."
        ExitWithErrorCode 0
    }
    catch {
        Write-Error $_
        Write-Log -Level ERROR -ExitCode 1 -Message "Set-WACNetworkServiceAccess: Failed to configure access for Network Service to the data folder and the configuration file. Error: $_"
        ExitWithErrorCode 1
        throw
    }
}

<#
.SYNOPSIS
    Gets if the current OS has a desktop.

.DESCRIPTION
    Gets if the current operating system has a desktop (e.g., Windows Client SKUs, non-core Windows Server SKUs, etc.).

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, 1 is error, 2 is early exit.

.EXAMPLE
    Get-WACHasDesktop
#>
function Get-WACHasDesktop {
    Param(
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    SetExitWithErrorCode $ExitWithErrorCode
    try {
        $productType = (Get-CimInstance -ClassName Win32_OperatingSystem).ProductType
        if ($productType -ne 1) {
            # check if it's Windows Workstation such as Windows Client ("1")
            $foundDesktop = @(Dism /online /Get-Packages /Format:List | Where-Object {$_ -like "*Microsoft-Windows-UserExperience-Desktop-Package*" } ).Count -eq 1
            if (-not $foundDesktop) {
                Write-Log -Level INFO -ExitCode 2 -Message "Get-WACHasDesktop: Current OS does not have desktop."
                ExitWithErrorCode 2
                return $false
            }
        }

        Write-Log -Level INFO -ExitCode 0 -Message "Get-WACHasDesktop: Current OS does have desktop."
        ExitWithErrorCode 0
        return $true
    }
    catch {
        Write-Error $_
        Write-Log -Level ERROR -ExitCode 1 -Message "Get-WACHasDesktop: Failed to determine if current OS has desktop. Error: $_"
        ExitWithErrorCode 1
        throw
    }
}

<#
.SYNOPSIS
    Starts the Windows Admin Center service.

.DESCRIPTION
    Starts the Windows Admin Center service.

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, otherwise error.

.EXAMPLE
    Start-WACService
#>
function Start-WACService {
    Param(
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    SetExitWithErrorCode $ExitWithErrorCode
    try {
        Start-Service -Name $ConstServiceName -ErrorAction Stop
        Write-Log -Level INFO -ExitCode 0 -Message "Start-WACService: Successfully started Windows Admin Center service."
        ExitWithErrorCode 0
    }
    catch {
        Write-Error $_
        Write-Log -Level ERROR -ExitCode 1 -Message "Start-WACService: Failed to start Windows Admin Center service. Error: $_"
        ExitWithErrorCode 1
        throw
    }
}

<#
.SYNOPSIS
    Starts Windows Admin Center through launcher.

.DESCRIPTION
    Starts Windows Admin Center through launcher if the current operating system has a desktop (e.g., Windows Client SKUs, non-core Windows Server SKUs, etc.). Otherwise returns early.

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, 1 is error, 2 is early exit.

.EXAMPLE
    Start-WACLauncher
#>
function Start-WACLauncher {
    Param(
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    SetExitWithErrorCode $ExitWithErrorCode
    try {
        $hasDesktop = Get-WACHasDesktop
        if (-not $hasDesktop) {
            Write-Log -Level INFO -ExitCode 2 -Message "Start-WACLauncher: Current OS does not have desktop. Exiting early."
            ExitWithErrorCode 2
            return
        }

        Start-Process -FilePath $ConstLauncherExecutableName -WorkingDirectory $ConstServiceFolderPath
        Write-Log -Level INFO -ExitCode 0 -Message "Start-WACLauncher: Successfully started Windows Admin Center launcher."
        ExitWithErrorCode 0
    }
    catch {
        Write-Error $_
        Write-Log -Level ERROR -ExitCode 1 -Message "Start-WACLauncher: Failed to start Windows Admin Center launcher. Error: $_"
        ExitWithErrorCode 1
        throw
    }
}

<#
.SYNOPSIS
    Gets the status of the Windows Admin Center service.

.DESCRIPTION
    Gets the status of the Windows Admin Center service and processes.

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, otherwise error.

.EXAMPLE
    Get-WACService
#>
function Get-WACService {
    Param(
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    SetExitWithErrorCode $ExitWithErrorCode
    try {
        Get-Service -Name $ConstServiceName -ErrorAction Stop
        Get-Process -Name $ConstServiceName -ErrorAction SilentlyContinue
        Write-Log -Level INFO -ExitCode 0 -Message "Get-WACService: Successfully got Windows Admin Center service status."
        ExitWithErrorCode 0
    }
    catch {
        Write-Error $_
        Write-Log -Level ERROR -ExitCode 1 -Message "Get-WACService: Failed to get Windows Admin Center service status. Error: $_"
        ExitWithErrorCode 1
        throw
    }
}

<#
.SYNOPSIS
    Gets the status of the Windows Admin Center Account Management service.

.DESCRIPTION
    Gets the status of the Windows Admin Center Account Management service.

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, otherwise error.

.EXAMPLE
    Get-WACAccountManagementService
#>
function Get-WACAccountManagementService {
    Param(
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    SetExitWithErrorCode $ExitWithErrorCode
    try {
        Get-Service -Name $ConstAccountManagementServiceName -ErrorAction Stop
        Write-Log -Level INFO -ExitCode 0 -Message "Get-WACAccountManagementService: Successfully got Windows Admin Center Account Management service status."
        ExitWithErrorCode 0
    }
    catch {
        Write-Error $_
        Write-Log -Level ERROR -ExitCode 1 -Message "Get-WACAccountManagementService: Failed to get Windows Admin Center Account Management service status. Error: $_"
        ExitWithErrorCode 1
        throw
    }
}

<#
.SYNOPSIS
    Gets the status of Windows Admin Center Updater scheduled task.

.DESCRIPTION
    Gets the status of Windows Admin Center Updater scheduled task.

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, otherwise error.

.EXAMPLE
    Get-WACUpdaterScheduledTask
#>
function Get-WACUpdaterScheduledTask {
    Param(
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    SetExitWithErrorCode $ExitWithErrorCode
    try {
        Get-ScheduledTask -TaskName $ConstUpdaterScheduledTaskName -ErrorAction Stop
        Write-Log -Level INFO -ExitCode 0 -Message "Get-WACUpdaterScheduledTask: Successfully got Windows Admin Center Updater scheduled task status."
        ExitWithErrorCode 0
    }
    catch {
        Write-Error $_
        Write-Log -Level ERROR -ExitCode 1 -Message "Get-WACUpdaterScheduledTask: Failed to get Windows Admin Center Updater scheduled task status. Error: $_"
        ExitWithErrorCode 1
        throw
    }
}

<#
.SYNOPSIS
    Stops the Windows Admin Center service.

.DESCRIPTION
    Stops the Windows Admin Center service if found on the system and is currently in the running state, otherwise returns early.

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, otherwise error.

.EXAMPLE
    Stop-WACService
#>
function Stop-WACService {
    Param(
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    SetExitWithErrorCode $ExitWithErrorCode
    try {
        $wacService = Get-Service -Name $ConstServiceName -ErrorAction SilentlyContinue
        if (($null -eq $wacService) -or ($wacService.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running)) {
            Write-Log -Level INFO -ExitCode 0 -Message "Stop-WACService: Windows Admin Center service is already stopped or not available."
        } else {
            Stop-Service -Name $ConstServiceName -Force -ErrorAction Stop
            Write-Log -Level INFO -ExitCode 0 -Message "Stop-WACService: Successfully stopped Windows Admin Center service."
        }

        ExitWithErrorCode 0
    }
    catch {
        Write-Error $_
        Write-Log -Level ERROR -ExitCode 1 -Message "Stop-WACService: Failed to stop Windows Admin Center. Error: $_"
        ExitWithErrorCode 1
        throw
    }
}

<#
.SYNOPSIS
    Stops the Windows Admin Center launcher.

.DESCRIPTION
    Stops the Windows Admin Center launcher if the current operating system has a desktop (e.g., Windows Client SKUs, non-core Windows Server SKUs, etc.) and the launcher process is launching. Otherwise returns early.

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, 1 is error, 2 is early exit.

.EXAMPLE
    Stop-WACLauncher
#>
function Stop-WACLauncher {
    Param(
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    SetExitWithErrorCode $ExitWithErrorCode
    try {
        $hasDesktop = Get-WACHasDesktop
        if (-not $hasDesktop) {
            Write-Log -Level INFO -ExitCode 2 -Message "Stop-WACLauncher: Current OS does not have desktop. Exiting early."
            ExitWithErrorCode 2
            return
        }

        $launcher = Get-Process -Name $ConstLauncherName -ErrorAction SilentlyContinue
        if ($null -ne $launcher) {
            $launcher | Stop-Process -Force
            Write-Log -Level INFO -ExitCode 0 -Message "Stop-WACLauncher: Successfully stopped Windows Admin Center Launcher."
        }
        
        ExitWithErrorCode 0
    }
    catch {
        Write-Error $_
        Write-Log -Level ERROR -ExitCode 1 -Message "Stop-WACLauncher: Failed to stop Windows Admin Center Launcher. Error: $_"
        ExitWithErrorCode 1
        throw
    }
}

<#
.SYNOPSIS
    Stops the Windows Admin Center Account Management service.

.DESCRIPTION
    Stops the Windows Admin Center Account Management service if currently in the running state, otherwise returns early.

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, otherwise error.

.EXAMPLE
    Stop-WACAccountManagementService
#>
function Stop-WACAccountManagementService {
    Param(
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    SetExitWithErrorCode $ExitWithErrorCode
    try {
        $wacService = Get-Service -Name $ConstAccountManagementServiceName
        if ($wacService.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running) {
            Write-Log -Level INFO -ExitCode 0 -Message "Stop-WACAccountManagementService: Windows Admin Center Account Management service is already stopped."
            ExitWithErrorCode 0
            return;
        }

        Stop-Service -Name $ConstAccountManagementServiceName -ErrorAction Stop
        Write-Log -Level INFO -ExitCode 0 -Message "Stop-WACAccountManagementService: Successfully stopped Windows Admin Center Account Management service."
        ExitWithErrorCode 0
    }
    catch {
        Write-Error $_
        Write-Log -Level ERROR -ExitCode 1 -Message "Stop-WACAccountManagementService: Failed to stop Windows Admin Center Account Management service. Error: $_"
        ExitWithErrorCode 1
        throw
    }
}

<#
.SYNOPSIS
    Stops the Windows Admin Center Updater scheduled task.

.DESCRIPTION
    Stops the Windows Admin Center Updater scheduled task if currently in the running state, otherwise returns early.

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, otherwise error.

.EXAMPLE
    Stop-WACUpdaterScheduledTask
#>
function Stop-WACUpdaterScheduledTask {
    Param(
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    SetExitWithErrorCode $ExitWithErrorCode
    try {
        $updaterService = Get-ScheduledTask -TaskName $ConstUpdaterScheduledTaskName
        if ($updaterService.State -ne [System.ServiceProcess.ServiceControllerStatus]::Running) {
            Write-Log -Level INFO -ExitCode 0 -Message "Stop-WACUpdaterScheduledTask: Windows Admin Center Updater scheduled task is already stopped."
            ExitWithErrorCode 0
            return;
        }

        Stop-ScheduledTask -TaskName $ConstUpdaterScheduledTaskName -ErrorAction Stop
        Write-Log -Level INFO -ExitCode 0 -Message "Stop-WACUpdaterScheduledTask: Successfully stopped Windows Admin Center Updater scheduled task."
        ExitWithErrorCode 0
    }
    catch {
        Write-Error $_
        Write-Log -Level ERROR -ExitCode 1 -Message "Stop-WACUpdaterScheduledTask: Failed to stop Windows Admin Center Updater scheduled task. Error: $_"
        ExitWithErrorCode 1
        throw
    }
}

<#
.SYNOPSIS
    Unregisters the Windows Admin Center service.

.DESCRIPTION
    Stops the Windows Admin Center service if running and then unregisters it.

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, otherwise error.

.EXAMPLE
    Unregister-WACService
#>
function Unregister-WACService {
    Param(
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    SetExitWithErrorCode $ExitWithErrorCode
    Stop-Service -Name $ConstServiceName -ErrorAction SilentlyContinue

    Invoke-WACWinCommand -Command $ConstServiceController -Parameters "delete", $ConstServiceName
    Write-Log -Level INFO -ExitCode 0 -Message "Unregister-WACService: Successfully unregistered Windows Admin Center service."
    ExitWithErrorCode 0
}

<#
.SYNOPSIS
    Unregisters the Windows Admin Center Account Management service.

.DESCRIPTION
    Stops the Windows Admin Center Account Management service if running and then unregisters it. If the CheckIfExist flag is used and the service does not exist, returns early.

.PARAMETER CheckIfExist
    Check if the service exists before attempting to unregister it.

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, otherwise error.

.EXAMPLE
    Unregister-WACAccountManagementService

.EXAMPLE
    Unregister-WACAccountManagementService -CheckIfExist
#>
function Unregister-WACAccountManagementService {
    Param(
        [Parameter(Mandatory = $false)]
        [switch]$CheckIfExist,
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    SetExitWithErrorCode $ExitWithErrorCode
    if ($CheckIfExist) {
        $service = Get-Service -Name $ConstAccountManagementServiceName -ErrorAction SilentlyContinue
        if ($service.Length -eq 0) {
            Write-Log -Level INFO -ExitCode 0 -Message "Unregister-WACAccountManagementService: Not found Windows Admin Center Account Management service."
            ExitWithErrorCode 0
            return
        }
    }

    Stop-Service -Name $ConstAccountManagementServiceName -ErrorAction SilentlyContinue

    Invoke-WACWinCommand -Command $ConstServiceController -Parameters "delete", $ConstAccountManagementServiceName
    Write-Log -Level INFO -ExitCode 0 -Message "Unregister-WACAccountManagementService: Successfully unregistered Windows Admin Center Account Management service."
    ExitWithErrorCode 0
}

<#
.SYNOPSIS
    Unregisters the Windows Admin Center Updater scheduled task.

.DESCRIPTION
    Stops the Windows Admin Center Updater scheduled task if running and then unregisters it.

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, otherwise error.

.EXAMPLE
    Unregister-WACUpdaterScheduledTask
#>
function Unregister-WACUpdaterScheduledTask {
    Param(
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    SetExitWithErrorCode $ExitWithErrorCode
    Stop-ScheduledTask -TaskName $ConstUpdaterScheduledTaskName -ErrorAction SilentlyContinue

    Unregister-ScheduledTask -TaskName $ConstUpdaterScheduledTaskName -Confirm:$false
    Write-Log -Level INFO -ExitCode 0 -Message "Unregister-WACUpdaterScheduledTask: Successfully unregistered Windows Admin Center Updater scheduled task."
    ExitWithErrorCode 0
}

<#
.SYNOPSIS
    Copies Windows Admin Center process files from installer from temp location to path to use for service registration.

.DESCRIPTION
    Copies Windows Admin Center Updater process files from installer from temp location to path to use for scheduled task registration.
    If the scheduled task is already registered, this function returns early in case the updater scheduled task is running the installer.
    Setting the Force switch will force the copy to occur.

.PARAMETER Force
    Force the copy to occur.

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, otherwise error.

.EXAMPLE
    Copy-WACTempUpdaterProcessFiles

.EXAMPLE
    Copy-WACTempUpdaterProcessFiles -Force
#>
function Copy-WACTempUpdaterProcessFiles {
    Param(
        [Parameter(Mandatory = $false)]
        [switch]$Force,
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    SetExitWithErrorCode $ExitWithErrorCode

    try {
        $scheduledTask = Get-ScheduledTask -TaskName $ConstUpdaterScheduledTaskName -ErrorAction SilentlyContinue
        if ($scheduledTask.Length -gt 0) {
            if ($Force -eq $false) {
                Write-Log -Level INFO -ExitCode 0 -Message "Copy-WACTempUpdaterProcessFiles: Windows Admin Center Updater scheduled task is already registered. Skipping copy."
                ExitWithErrorCode 0
                return
            }

            Stop-WACUpdaterScheduledTask -ExitWithErrorCode:$false
        }

        Copy-Item -Path "$ConstServiceFolderPath\*" -Destination $ConstUpdaterFolderPath `
            -Exclude $("$ConstServiceName.*", "$ConstAccountManagementServiceName.*", "$ConstLauncherName.*", $ConstEntityFrameworkBundleFileName) -Recurse -Force
        Copy-Item -Path "$ConstServiceFolderPath\$ConstUpdaterExecutableName" -Destination $ConstUpdaterFolderPath -Force
        Write-Log -Level INFO -ExitCode 0 -Message "Copy-WACTempUpdaterProcessFiles: Successfully copied Windows Admin Center Updater process files."
        ExitWithErrorCode 0
    }
    catch {
        Write-Error $_
        Write-Log -Level ERROR -ExitCode 1 -Message "Copy-WACTempUpdaterProcessFiles: Failed to copy Windows Admin Center Updater process files. Error: $_"
        ExitWithErrorCode 1
        throw
    }
}

<#
.SYNOPSIS
    Creates the Windows Admin Center event log and configures it.

.DESCRIPTION
    Creates the Windows Admin Center event log sources underneath the WindowsAdminCenter log name and configures the event logs underneath the log name.

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, otherwise error.

.EXAMPLE
    New-WACEventLog
#>
function New-WACEventLog {
    Param(
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    SetExitWithErrorCode $ExitWithErrorCode
    try {
        if (!(AssertEventLogExists($ConstEventLogName))) {
            CreateEventSources
        }   
    }
    catch {
        Write-Error $_
        Write-Log -Level ERROR -ExitCode 1 -Message "New-WACEventLog: Failed to create Windows Admin Center event log. Error: $_"
        ExitWithErrorCode 1
        throw
    }

    $hundredMegaByte = 100 * 1024 * 1024
    Invoke-WACWinCommand -Command $ConstWevutilCommand -Parameters "set-log $ConstEventLogName /ms:$hundredMegaByte"
    Write-Log -Level INFO -ExitCode 0 -Message "New-WACEventLog: Successfully created Windows Admin Center event log."
    ExitWithErrorCode 0
}

<#
.SYNOPSIS
    Removes the Windows Admin Center event log.

.DESCRIPTION
    Removes the Windows Admin Center event log.

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, otherwise error.

.EXAMPLE
    Remove-WACEventLog
#>
function Remove-WACEventLog {
    Param(
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    SetExitWithErrorCode $ExitWithErrorCode
    try {
        Remove-EventLog -LogName $ConstEventLogName
        Write-Log -Level INFO -ExitCode 0 -Message "Remove-WACEventLog: Successfully removed Windows Admin Center event log."
        ExitWithErrorCode 0
    }
    catch {
        Write-Error $_
        Write-Log -Level ERROR -ExitCode 1 -Message "Remove-WACEventLog: Failed to remove Windows Admin Center event log. Error: $_"
        ExitWithErrorCode 1
        throw
    }
}

<#
.SYNOPSIS
    Creates a new self signed certificate.

.DESCRIPTION
    Creates a new self signed certificate. The certificate is signed by a root CA certificate that is also created.

.PARAMETER ExpirePeriodYears
    Number of years before expiration of certificate. (default is 0 years).

.PARAMETER ExpirePeriodDays
    Number of days before expiration of certificate. (default is 60 days).

.PARAMETER ExcludeLocalhost
    Exclude localhost for allowed connections. (default is allowed).

.PARAMETER ExcludeMachineName
    Exclude machine name for allowed connections. (default is allowed).

.PARAMETER Fqdn
    FQDN of host name accessed externally. (no default).

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, otherwise error.

.EXAMPLE
    New-WACSelfSignedCertificate

.EXAMPLE
    New-WACSelfSignedCertificate -ExpirePeriodYears 1 -ExpirePeriodDays 0 -ExcludeLocalhost -ExcludeMachineName -Fqdn "myserver.contoso.com"
#>
function New-WACSelfSignedCertificate {
    Param( 
        [Parameter(Mandatory = $false)]
        [int]$ExpirePeriodYears = 0,
        [Parameter(Mandatory = $false)]
        [int]$ExpirePeriodDays = 60,
        [Parameter(Mandatory = $false)]
        [switch]$ExcludeLocalhost,
        [Parameter(Mandatory = $false)]
        [switch]$ExcludeMachineName,
        [Parameter(Mandatory = $false)]
        [string]$Fqdn,
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    SetExitWithErrorCode $ExitWithErrorCode

    $alternameNames = @()
    if (-not $ExcludeLocalhost) {
        $alternameNames += "localhost"
    }

    if (-not $ExcludeMachineName) {
        $alternameNames += [System.Environment]::MachineName
    }

    if (-not [System.string]::IsNullOrWhiteSpace($Fqdn)) {
        $alternameNames += $Fqdn
    }

    if ($alternameNames.Length -eq 0) {
        Write-Error -Message "A network name such as localhost, machine name, or FQDN must be provided."
        $errorMessage = "New-WACSelfSignedCertificate: Failed to create self signed certificate. Error: A network name such as localhost, machine name, or FQDN must be provided."
        Write-Log -Level ERROR -ExitCode 1 -Message $errorMessage
        ExitWithErrorCode 1
        throw $errorMessage
    }

    try {
        $fileSecurity = New-Object System.Security.AccessControl.FileSecurity
        $fileSecurity.SetSecurityDescriptorSddlForm($ConstCertificateKeySecurityDescriptor)
        $expired = (Get-Date).AddYears($ExpirePeriodYears).AddDays($ExpirePeriodDays)

        # Create Root CA/Signer. This will  be used to sign the SSL certificate.
        $rootCACertArguments = @{
            Subject            = $ConstRootCACertificateSubjectName
            DnsName            = $alternameNames
            KeyAlgorithm       = "RSA"
            KeyLength          = 2048
            KeyUsage           = "CertSign", "CrlSign", "DigitalSignature"
            TextExtension      = "2.5.29.37={text}1.3.6.1.5.5.7.3.1", "2.5.29.19={text}CA=true"
            HashAlgorithm      = "SHA512"
            Provider           = "Microsoft Enhanced RSA and AES Cryptographic Provider"
            CertStoreLocation  = "Cert:\LocalMachine\My"
            NotAfter           = $expired
            SecurityDescriptor = $fileSecurity
        }
        $rootCACertificate = New-SelfSignedCertificate @rootCACertArguments

        # Create self-signed certificate signed by the Root CA
        $sslCertArguments = @{
            Subject            = $ConstSSLCertificateSubjectName
            DnsName            = $alternameNames
            KeyAlgorithm       = "RSA"
            KeyLength          = 2048
            KeyUsage           = "DigitalSignature", "KeyEncipherment", "DataEncipherment"
            TextExtension      = "2.5.29.37={text}1.3.6.1.5.5.7.3.1"
            HashAlgorithm      = "SHA512"
            Provider           = "Microsoft Enhanced RSA and AES Cryptographic Provider"
            CertStoreLocation  = "Cert:\LocalMachine\My"
            NotAfter           = $expired
            SecurityDescriptor = $fileSecurity
            Signer             = $rootCACertificate
        }
        $certificate = New-SelfSignedCertificate @sslCertArguments

        # Install the Root CA certificate to the "Trusted Root Certificate Authorities" store and remove it from the Personal store
        $tempPath = [System.IO.Path]::GetTempFileName();
        Export-Certificate -Cert $rootCACertificate -FilePath $tempPath -Type CERT -ErrorAction Stop | Out-Null
        Import-Certificate -FilePath $tempPath -CertStoreLocation Cert:\LocalMachine\Root -ErrorAction Stop | Out-Null
        Remove-Item -Force $rootCACertificate.PSPath | Out-Null
        Write-Host $certificate
        Write-Log -Level INFO -ExitCode 0 -Message "New-WACSelfSignedCertificate: Successfully created self signed certificate."
        ExitWithErrorCode 0
    }
    catch {
        Write-Error $_
        Write-Log -Level ERROR -ExitCode 1 -Message "New-WACSelfSignedCertificate: Failed to create self signed certificate. Error: $_"
        ExitWithErrorCode 1
        throw
    }
}

<#
.SYNOPSIS
    Creates a new test self signed certificate for extension sideloading.

.DESCRIPTION
    Creates a new test self signed certificate for extension sideloading. The certificate is signed by a root CA certificate that is also created.

.PARAMETER Password
    Password to assign to exported .pfx file. (default is !@#123abc).

.PARAMETER OutputFolderPath
    Path to output folder to export .pfx file. (default is C:\temp\Certificates).

.PARAMETER RootCASubjectName
    The subject name of the root CA certificate. (default to $ConstTestRootCACertificateSubjectName)

.PARAMETER SslCertificateSubjectName
    The subject name of the SSL certificate. (default to $ConstTestSSLCertificateSubjectName)

.PARAMETER KeepAllFiles
    If set, will keep all files generated by this script. If not set, only files needed for sideloading will be kept. (default is false).

.PARAMETER ExpirePeriodYears
    Number of years before expiration of certificate. (default is 10 years).

.PARAMETER ExpirePeriodDays
    Number of days before expiration of certificate. (default is 0 days).

.PARAMETER ExcludeLocalhost
    Exclude localhost for allowed connections. (default is allowed).

.PARAMETER MachineName
    Machine name for allowed connections. (no default).

.PARAMETER Fqdn
    FQDN of host name accessed externally. (no default).

.EXAMPLE
    New-WACTestSelfSignedCertificate

.EXAMPLE
    New-WACTestSelfSignedCertificate -Password "xxxxxxxxx" -OutputFolderPath "C:\temp\Certificates" -RootCASubjectName "MyRootCA" -SslCertificateSubjectName "MySSLCertificate" -KeepAllFiles -ExpirePeriodYears 10 -ExpirePeriodDays 0 -ExcludeLocalhost -MachineName "MyMachine" -Fqdn "myserver.contoso.com"
#>
function New-WACTestSelfSignedCertificate {
    Param(
        [Parameter(Mandatory = $false)]
        [String]$Password = "xxxxxxxxx",
        [Parameter(Mandatory = $false)]
        [String]$OutputFolderPath = "C:\temp\Certificates",
        [Parameter(Mandatory = $false)]
        [String]$RootCASubjectName,
        [Parameter(Mandatory = $false)]
        [String]$SslCertificateSubjectName,
        [Parameter(Mandatory = $false)]
        [switch]$KeepAllFiles = $false,
        [Parameter(Mandatory = $false)]
        [int]$ExpirePeriodYears = 10,
        [Parameter(Mandatory = $false)]
        [int]$ExpirePeriodDays = 0,
        [Parameter(Mandatory = $false)]
        [switch]$ExcludeLocalhost,
        [Parameter(Mandatory = $false)]
        [string]$MachineName,
        [Parameter(Mandatory = $false)]
        [string]$Fqdn
    )

    $openssl = "c:\Program Files\Git\usr\bin\openssl.exe"
    if (!(Test-Path -Path $openssl)) {
        Write-Error -Message "OpenSSL not found at $openssl"
        return
    }

    if (!(Test-Path -Path $OutputFolderPath)) {
        New-Item -Path $OutputFolderPath -ItemType "directory" -Force
    }

    $alternameNames = @()
    if (-not $ExcludeLocalhost) {
        $alternameNames += "localhost"
    }

    if (-not [System.string]::IsNullOrWhiteSpace($MachineName)) {
        $alternameNames += $MachineName

        if ($RootCASubjectName -eq "") {
            $RootCASubjectName = "$MachineName-$ConstTestRootCACertificateSubjectName"
        }

        if ($SslCertificateSubjectName -eq "") {
            $SslCertificateSubjectName = "$MachineName-$ConstTestSSLCertificateSubjectName"
        }
    }

    if ($RootCASubjectName -eq "") {
        $RootCASubjectName = $ConstTestRootCACertificateSubjectName
    }

    if ($SslCertificateSubjectName -eq "") {
        $SslCertificateSubjectName = $ConstTestSSLCertificateSubjectName
    }

    Remove-WACTestSelfSignedCertificates -RootCACertificateSubjectCN "CN=$RootCASubjectName" -SSLCertificateSubjectCN "CN=$SslCertificateSubjectName"

    if (-not [System.string]::IsNullOrWhiteSpace($Fqdn)) {
        $alternameNames += $Fqdn
    }

    try {
        $fileSecurity = New-Object System.Security.AccessControl.FileSecurity
        $fileSecurity.SetSecurityDescriptorSddlForm($ConstCertificateKeySecurityDescriptor)
        $expired = (Get-Date).AddYears($ExpirePeriodYears).AddDays($ExpirePeriodDays)

        # Create Root CA/Signer. This will  be used to sign the SSL certificate.
        $rootCACertArguments = @{
            Subject            = $RootCASubjectName
            DnsName            = $alternameNames
            KeyAlgorithm       = "RSA"
            KeyLength          = 2048
            KeyUsage           = "CertSign", "CrlSign", "DigitalSignature"
            TextExtension      = "2.5.29.37={text}1.3.6.1.5.5.7.3.1", "2.5.29.19={text}CA=true"
            HashAlgorithm      = "SHA512"
            Provider           = "Microsoft Enhanced RSA and AES Cryptographic Provider"
            CertStoreLocation  = "Cert:\LocalMachine\My"
            NotAfter           = $expired
            SecurityDescriptor = $fileSecurity
        }
        $rootCACertificate = New-SelfSignedCertificate @rootCACertArguments

        # Create self-signed certificate signed by the Root CA
        $sslCertArguments = @{
            Subject            = $SslCertificateSubjectName
            DnsName            = $alternameNames
            KeyAlgorithm       = "RSA"
            KeyLength          = 2048
            KeyUsage           = "DigitalSignature", "KeyEncipherment", "DataEncipherment"
            TextExtension      = "2.5.29.37={text}1.3.6.1.5.5.7.3.1"
            HashAlgorithm      = "SHA512"
            Provider           = "Microsoft Enhanced RSA and AES Cryptographic Provider"
            CertStoreLocation  = "Cert:\LocalMachine\My"
            NotAfter           = $expired
            SecurityDescriptor = $fileSecurity
            Signer             = $rootCACertificate
        }
        $certificate = New-SelfSignedCertificate @sslCertArguments

        # Install the Root CA certificate to the "Trusted Root Certificate Authorities" store and remove it from the Personal store
        $caPath = "$OutputFolderPath\$RootCASubjectName.cer"
        Export-Certificate -Cert $rootCACertificate -FilePath $caPath -Type CERT -ErrorAction Stop | Out-Null
        Import-Certificate -FilePath $caPath -CertStoreLocation Cert:\LocalMachine\Root -ErrorAction Stop | Out-Null
        Remove-Item -Force $rootCACertificate.PSPath | Out-Null
        Write-Host $certificate

        # Export the certificate to a .pfx file
        $certPath = "$OutputFolderPath\$SslCertificateSubjectName"
        $export = Export-PfxCertificate -Cert $certificate -FilePath "$certPath.pfx" -Password (ConvertTo-SecureString -String $Password -Force -AsPlainText) -ErrorAction Stop
        Write-Host "Certificate exported to $export"

        $pass = "pass:$Password"
        Invoke-Expression "& `"$openssl`" pkcs12 -nocerts -passin $pass -passout $pass -in `"$certPath.pfx`" -out `"$certPath.key.pem`""
        Write-Host "Created PEM KEY file"
        Invoke-Expression "& `"$openssl`" pkcs12 -nokeys -passin $pass -in `"$certPath.pfx`" -out `"$certPath.cert.pem`""
        Write-Host "Created PEM CERT file"
        Invoke-Expression "& `"$openssl`" rsa -passin $pass -in `"$certPath.key.pem`" -out `"$certPath.rawkey.pem`""
        Write-Host "Exposed KEY with RAWKEY file for ng serve usage"

        if ($KeepAllFiles) {
            Invoke-Expression "& `"$openssl`" pkcs12 -password $pass -passin $pass -passout $pass -in `"$certPath.pfx`" -out `"$certPath.pem`""
            Write-Host "Created PEM file"
        } else {
            Remove-Item "$certPath.key.pem" -Force
        }
    }
    catch {
        Write-Error $_
    }
}

<#
.SYNOPSIS
    Import the test self signed root CA certificate to setup sideloading.

.DESCRIPTION
    Import the test self signed root CA certificate to the target machine for sideloading extensions.

.PARAMETER CertificateFolderPath
    The path to folder containing the root CA certificate and SSL certificate. (default to C:\temp\Certificates)

.PARAMETER RootCAFileName
    The name of the root CA certificate file. (default to $ConstTestRootCACertificateSubjectName)

.PARAMETER SslCertificateFileName
    The name of the SSL certificate file. (default to $ConstTestSSLCertificateSubjectName)

.PARAMETER RemoteMachineName
    Name of the remote machine to import the certificate to. (default is localhost).

.PARAMETER RemoteMachineCredential
    Credential to use to connect to the remote machine. (default is current user).

.PARAMETER Password
    Password to use to import SSL .pfx file. (default is !@#123abc).

.EXAMPLE
    Import-WACTestSelfSignedCertificates

.EXAMPLE
    Import-WACTestSelfSignedCertificates -CertificateFolderPath "C:\temp\Certificates" -RootCAFileName "MyRootCA" -SslCertificateFileName "MySSLCertificate" -RemoteMachineName "MyMachine" -RemoteMachineCredential $credential -Password "xxxxxxxxx"
#>
function Import-WACTestSelfSignedCertificates {
    Param(
        [Parameter(Mandatory = $false)]
        [String]$CertificateFolderPath = "C:\temp\Certificates",
        [Parameter(Mandatory = $false)]
        [String]$RootCAFileName,
        [Parameter(Mandatory = $false)]
        [String]$SslCertificateFileName,
        [Parameter(Mandatory = $false)]
        [String]$RemoteMachineName,
        [Parameter(Mandatory = $false)]
        [pscredential]$RemoteMachineCredential,
        [Parameter(Mandatory = $false)]
        [String]$CertificatePassword = "xxxxxxxxx"
    )

    try {
        if ($RootCAFileName -eq "") {
            if ($RemoteMachineName -eq "") {
                $RootCAFileName = $ConstTestRootCACertificateSubjectName
            } else {
                $RootCAFileName = "$RemoteMachineName-$ConstTestRootCACertificateSubjectName"
            }
        }

        if ($SslCertificateFileName -eq "") {
            if ($RemoteMachineName -eq "") {
                $SslCertificateFileName = $ConstTestSSLCertificateSubjectName
            } else {
                $SslCertificateFileName = "$RemoteMachineName-$ConstTestSSLCertificateSubjectName"
            }
        }

        $RootCAFilePath = "$CertificateFolderPath\$RootCAFileName.cer"
        $SslCertificateFilePath = "$CertificateFolderPath\$SslCertificateFileName.pfx"
        if ($RemoteMachineName -eq "") {
            Import-Certificate -FilePath $RootCAFilePath -CertStoreLocation Cert:\LocalMachine\Root -ErrorAction Stop | Out-Null
            $ssl = Import-PfxCertificate -FilePath $SslCertificateFilePath -Password (ConvertTo-SecureString -String $CertificatePassword -Force -AsPlainText) -CertStoreLocation Cert:\LocalMachine\My -ErrorAction Stop

            Set-WACCertificateAcl -SubjectName $ssl.SubjectName

            $output = "Imported SSL thumbprint (use with WAC install): $($ssl.Thumbprint)"
        } else {
            $sessionParamters = @{
                ComputerName = $RemoteMachineName
            }

            if ($RemoteMachineCredential -ne $null) {
                $sessionParamters.Add("Credential", $RemoteMachineCredential)
            }

            $session = New-PSSession @sessionParamters
            $caTempPath = Invoke-Command -Session $session -ScriptBlock {
                $caTempPath = [System.IO.Path]::GetTempFileName()
                return $caTempPath
            }
            $sslTempPath = Invoke-Command -Session $session -ScriptBlock {
                $sslTempPath = [System.IO.Path]::GetTempFileName()
                return $sslTempPath
            }

            Copy-Item -Path $RootCAFilePath -Destination $caTempPath -ToSession $session -ErrorAction Stop
            Copy-Item -Path $SslCertificateFilePath -Destination $sslTempPath -ToSession $session -ErrorAction Stop
            $output = Invoke-Command -Session $session -ScriptBlock {
                Import-Certificate -FilePath $using:caTempPath -CertStoreLocation Cert:\LocalMachine\Root -ErrorAction Stop | Out-Null
                $ssl = Import-PfxCertificate -FilePath $using:sslTempPath -Password (ConvertTo-SecureString -String $using:CertificatePassword -Force -AsPlainText) -CertStoreLocation Cert:\LocalMachine\My -ErrorAction Stop

                $keyName = $ssl.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName
                $machineKeyPath = [IO.Path]::Combine($using:ConstMachineKeyRootPath, $keyName)

                if (Test-Path -Path $machineKeyPath) {
                    $acl = Get-Acl -Path $machineKeyPath
                    $networkServiceSid = New-Object System.Security.Principal.SecurityIdentifier -ArgumentList $using:ConstNetworkServiceSid
                    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule $networkServiceSid,$using:ConstFullControlPermissions,allow
                    $acl.AddAccessRule($rule)

                    Set-Acl -Path $machineKeyPath -AclObject $acl
                }

                return "Imported SSL thumbprint (use with WAC install): $($ssl.Thumbprint)"
            }

            Write-Host "Successfully imported certificate. $output"
        }
    }
    catch {
        Write-Error "Failed to import certificate. Error: $_"
    }
}

<#
.SYNOPSIS
    Gets all self signed certificates for Windows Admin Center.

.DESCRIPTION
    Gets all self signed certificates for Windows Admin Center.

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, otherwise error.

.EXAMPLE
    Get-WACSelfSignedCertificate
#>
function Get-WACSelfSignedCertificate {
    Param(
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    SetExitWithErrorCode $ExitWithErrorCode
    try {
        Get-Item -Path Cert:LocalMachine\My\* -ErrorAction Stop | Where-Object { $_.Subject -eq $ConstSSLCertificateSubjectCN }
        Write-Log -Level INFO -ExitCode 0 -Message "Get-WACSelfSignedCertificate: Successfully retrieved self signed certificate."
        ExitWithErrorCode 0
    }
    catch {
        Write-Error $_
        Write-Log -Level ERROR -ExitCode 1 -Message "Get-WACSelfSignedCertificate: Failed to retrieve self signed certificate. Error: $_"
        ExitWithErrorCode 1
        throw
    }
}

<#
.SYNOPSIS
    Gets all test self signed certificates for Windows Admin Center.

#>
function Get-WACTestSelfSignedCertificate {
    Get-Item -Path Cert:LocalMachine\My\* -ErrorAction Stop | Where-Object { $_.Subject -eq $ConstTestSSLCertificateSubjectCN }
}

<#
.SYNOPSIS
    Removes all self signed certificates for Windows Admin Center.

.DESCRIPTION
    Removes all self signed certificates and root CAs for Windows Admin Center.

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, otherwise error.

.EXAMPLE
    Remove-WACSelfSignedCertificates
#>
function Remove-WACSelfSignedCertificates {
    Param(
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    SetExitWithErrorCode $ExitWithErrorCode
    try {
        Get-Item Cert:LocalMachine\My\* | Where-Object { $_.Subject -eq $ConstSSLCertificateSubjectCN } | Remove-Item -ErrorAction Stop
        Get-Item Cert:LocalMachine\Root\* | Where-Object { $_.Subject -eq $ConstRootCACertificateSubjectCN } | Remove-Item -ErrorAction Stop
        Write-Log -Level INFO -ExitCode 0 -Message "Remove-WACSelfSignedCertificates: Successfully removed self signed certificate."
        ExitWithErrorCode 0
    }
    catch {
        Write-Error $_
        Write-Log -Level ERROR -ExitCode 1 -Message "Remove-WACSelfSignedCertificates: Failed to remove self signed certificate. Error: $_"
        ExitWithErrorCode 1
        throw
    }
}

<#
.SYNOPSIS
    Removes test self signed certificates for Windows Admin Center.

.DESCRIPTION
    Removes all test self signed certificates and root CAs for Windows Admin Center.

.PARAMETER SSLCertificateSubjectCN
    Subject CN of the test SSL certificate. (default to $ConstTestSSLCertificateSubjectCN)

.PARAMETER RootCACertificateSubjectCN
    Subject CN of the test root CA certificate. (default to $ConstTestRootCACertificateSubjectCN)

.EXAMPLE
    Remove-WACTestSelfSignedCertificates

.EXAMPLE
    Remove-WACTestSelfSignedCertificates -SSLCertificateSubjectCN "MySSLCertificate" -RootCACertificateSubjectCN "MyRootCA"
#>
function Remove-WACTestSelfSignedCertificates {
    Param(
        [Parameter(Mandatory = $false)]
        [string]$SSLCertificateSubjectCN = $ConstTestSSLCertificateSubjectCN,
        [Parameter(Mandatory = $false)]
        [string]$RootCACertificateSubjectCN = $ConstTestRootCACertificateSubjectCN
    )

    $sslCertificate = Get-Item Cert:LocalMachine\My\* | Where-Object { $_.Subject -eq $SSLCertificateSubjectCN }
    if ($null -ne $sslCertificate) {
        $sslCertificate | Remove-Item -ErrorAction Stop
    }

    $caCertificate = Get-Item Cert:LocalMachine\Root\* | Where-Object { $_.Subject -eq $RootCACertificateSubjectCN}
    if ($null -ne $caCertificate) {
        $caCertificate | Remove-Item -ErrorAction Stop
    }
}

<#
.SYNOPSIS
    Registers configuration of HTTP.SYS.

.DESCRIPTION
    Registers configuration of HTTP.SYS with the port and the certificate specified.

.PARAMETER Thumbprint
    The thumbprint of TLS certificate installed on LocalMachine store. (default uses CN=WindowsAdminCenterSelfSigned certificate from local machine store).

.PARAMETER Port
    The port number of HTTPS connection. Default port number is 6600.

.PARAMETER UserMode
    Configure the port for all users on the computer instead of Network Service. This option is not usually required.

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, otherwise error.

.EXAMPLE
    Register-WACHttpSys

.EXAMPLE
    Register-WACHttpSys -Thumbprint "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" -Port 6600 -UserMode
#>
function Register-WACHttpSys {
    Param(
        [Parameter(Mandatory = $false)]
        [string]$Thumbprint,
        [Parameter(Mandatory = $false)]
        [int]$Port = $ConstDefaultPort,
        [Parameter(Mandatory = $false)]
        [switch]$UserMode,
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    SetExitWithErrorCode $ExitWithErrorCode
    $securityDescriptor = if ($UserMode) { $ConstUsersSecurityDescriptor } else { $ConstNetworkServiceSecurityDescriptor }
    if ([System.string]::IsNullOrWhiteSpace($Thumbprint)) {
        $certificates = Get-Item Cert:LocalMachine\My\* | Where-Object { $_.Subject -eq 'CN=WindowsAdminCenterSelfSigned' }
        if ($null -eq $certificates) {
            Write-Error -Message "Thumbprint is required or no self-signed certificate exits."
            $errorMessage = "Register-WACHttpSys: Thumbprint is required or no self-signed certificate exits."
            Write-Log -Level ERROR -ExitCode 1 -Message $errorMessage
            ExitWithErrorCode 1
            throw $errorMessage
        }

        $certificate = if ($certificates.Length -ne 1) { $certificates[0] } else { $certificates }
        $Thumbprint = $certificate.Thumbprint
    }

    Invoke-WACWinCommand -Command $ConstNetShCommand -Parameters "http", "add", "sslcert", "ipport=0.0.0.0:$port", "certhash=$Thumbprint", "appid=""$ConstAppId""" -NoExit
    Invoke-WACWinCommand -Command $ConstNetShCommand -Parameters "http", "add", "urlacl", "url=https://+:$port/", "sddl=`"$securityDescriptor`""
    Write-Log -Level INFO -ExitCode 0 -Message "Register-WACHttpSys: Successfully registered HTTP.SYS configuration."
    ExitWithErrorCode 0
}

<#
.SYNOPSIS
    Gets configuration of HTTP.SYS.

.DESCRIPTION
    Gets configuration of HTTP.SYS with the port number specified.

.PARAMETER Port
    The port number of HTTPS connection. Default port number is 6600.

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, otherwise error.

.EXAMPLE
    Get-WACHttpSys

.EXAMPLE
    Get-WACHttpSys -Port 6600
#>
function Get-WACHttpSys {
    Param(
        [Parameter(Mandatory = $false)]
        [int]$Port = $ConstDefaultPort,
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    SetExitWithErrorCode $ExitWithErrorCode
    Invoke-WACWinCommand -Command $ConstNetShCommand -Parameters "http", "show", "sslcert", "ipport=0.0.0.0:$port" -NoExit
    Invoke-WACWinCommand -Command $ConstNetShCommand -Parameters "http", "show", "urlacl", "url=https://+:$port/" -NoExit
    Write-Log -Level INFO -ExitCode 0 -Message "Get-WACHttpSys: Successfully retrieved HTTP.SYS configuration."
    ExitWithErrorCode 0
}

<#
.SYNOPSIS
    Unregisters configuration of HTTP.SYS.

.DESCRIPTION
    Unregisters configuration of HTTP.SYS with the port number specified.

.PARAMETER Port
    The port number of HTTPS connection. Default port number is 6600.

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, otherwise error.

.EXAMPLE
    Unregister-WACHttpSys

.EXAMPLE
    Unregister-WACHttpSys -Port 6600
#>
function Unregister-WACHttpSys {
    Param(
        [Parameter(Mandatory = $false)]
        [int]$Port = $ConstDefaultPort,
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    SetExitWithErrorCode $ExitWithErrorCode
    Invoke-WACWinCommand -Command $ConstNetShCommand -Parameters "http", "delete", "sslcert", "ipport=0.0.0.0:$port"
    Invoke-WACWinCommand -Command $ConstNetShCommand -Parameters "http", "delete", "urlacl", "url=https://+:$port/" -NoExit
    Write-Log -Level INFO -ExitCode 0 -Message "Unregister-WACHttpSys: Successfully unregistered HTTP.SYS configuration."
    ExitWithErrorCode 0
}

<#
.SYNOPSIS
    Sets WAC install date.

.DESCRIPTION
    Sets the WAC install date in appsettings.json under %ProgramFiles%\WindowsAdminCenter to the current date.

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, otherwise error.

.EXAMPLE
    Set-WACInstallDate
#>
function Set-WACInstallDate {
    Param(
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    SetExitWithErrorCode $ExitWithErrorCode
    try {
        $currentDate = Get-Date -Format "yyyyMMdd"
        UpdateJsonField -Path (GetAppSettingsPath) -Sections "WindowsAdminCenter", "System", "InstallDate" -Value $currentDate
        ExitWithErrorCode 0
    }
    catch {
        Write-Error $_
        Write-Log -Level ERROR -ExitCode 1 -Message "Set-WACInstallDate: Failed to set WAC install date. Error: $_"
        ExitWithErrorCode 1
        throw
    }
}

<#
.SYNOPSIS
    Gets WAC install date.

.DESCRIPTION
    Gets the WAC install date in appsettings.json under %ProgramFiles%\WindowsAdminCenter.

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, otherwise error.

.EXAMPLE
    Get-WACInstallDate
#>
function Get-WACInstallDate {
    Param(
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    SetExitWithErrorCode $ExitWithErrorCode
    GetJsonField -Path (GetAppSettingsPath) -Sections "WindowsAdminCenter", "System", "InstallDate"
    Write-Log -Level INFO -ExitCode 0 -Message "Get-WACInstallDate: Successfully retrieved WAC install date."
    ExitWithErrorCode 0
}

<#
.SYNOPSIS
    Sets WAC file version.

.DESCRIPTION
    Sets the WAC file version in appsettings.json under %ProgramFiles%\WindowsAdminCenter to the given version.

.PARAMETER FileVersion
    The file version to set.

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, otherwise error.

.EXAMPLE
    Set-WACFileVersion -FileVersion "1.0.0.0"
#>
function Set-WACFileVersion {
    Param(
        [Parameter(Mandatory = $true)]
        [string]$FileVersion,
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    SetExitWithErrorCode $ExitWithErrorCode
    try {
        UpdateJsonField -Path (GetAppSettingsPath) -Sections "WindowsAdminCenter", "System", "FileVersion" -Value $FileVersion
        ExitWithErrorCode 0
    }
    catch {
        Write-Error $_
        Write-Log -Level ERROR -ExitCode 1 -Message "Set-WACFileVersion: Failed to set WAC file version. Error: $_"
        ExitWithErrorCode 1
        throw
    }
}

<#
.SYNOPSIS
    Gets WAC file version.

.DESCRIPTION
    Gets the WAC file version in appsettings.json under %ProgramFiles%\WindowsAdminCenter.

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, otherwise error.

.EXAMPLE
    Get-WACFileVersion
#>
function Get-WACFileVersion {
    Param(
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    SetExitWithErrorCode $ExitWithErrorCode
    GetJsonField -Path (GetAppSettingsPath) -Sections "WindowsAdminCenter", "System", "FileVersion"
    Write-Log -Level INFO -ExitCode 0 -Message "Get-WACFileVersion: Successfully retrieved WAC file version."
    ExitWithErrorCode 0
}

<#
.SYNOPSIS
    Sets WAC NuGet version.

.DESCRIPTION
    Sets the WAC NuGet version in appsettings.json under %ProgramFiles%\WindowsAdminCenter to the given version.

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, otherwise error.

.EXAMPLE
    Set-WACNuGetVersion -NuGetVersion "1.0.0-dev.0"
#>
function Set-WACNuGetVersion {
    Param(
        [Parameter(Mandatory = $true)]
        [string]$NuGetVersion,
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    SetExitWithErrorCode $ExitWithErrorCode
    try {
        UpdateJsonField -Path (GetAppSettingsPath) -Sections "WindowsAdminCenter", "System", "NuGetVersion" -Value $NuGetVersion
        ExitWithErrorCode 0
    }
    catch {
        Write-Error $_
        Write-Log -Level ERROR -ExitCode 1 -Message "Set-WACNuGetVersion: Failed to set WAC NuGet version. Error: $_"
        ExitWithErrorCode 1
        throw
    }
}

<#
.SYNOPSIS
    Gets WAC NuGetVersion.

.DESCRIPTION
    Gets the WAC NuGet version in appsettings.json under %ProgramFiles%\WindowsAdminCenter.

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, otherwise error.

.EXAMPLE
    Get-WACNuGetVersion
#>
function Get-WACNuGetVersion {
    Param(
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    SetExitWithErrorCode $ExitWithErrorCode
    GetJsonField -Path (GetAppSettingsPath) -Sections "WindowsAdminCenter", "System", "NuGetVersion"
    Write-Log -Level INFO -ExitCode 0 -Message "Get-WACNuGetVersion: Successfully retrieved WAC NuGet version."
    ExitWithErrorCode 0
}

<#
.SYNOPSIS
    Enables PowerShell remoting.

.DESCRIPTION
    Starts and configures PowerShell remoting.
    
.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, otherwise error.

.EXAMPLE
    Enable-WACPSRemoting
#>
function Enable-WACPSRemoting {
    Param(
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    SetExitWithErrorCode $ExitWithErrorCode
    try {
        Enable-PSRemoting -SkipNetworkProfileCheck -Force -ErrorAction Stop
        Write-Log -Level INFO -ExitCode 0 -Message "Enable-WACPSRemoting: Successfully configured PowerShell Remoting."
        ExitWithErrorCode 0
    }
    catch {
        Write-Error $_
        Write-Log -Level ERROR -ExitCode 1 -Message "Enable-WACPSRemoting: Failed to configure PowerShell Remoting. Error: $_"
        ExitWithErrorCode 1
        throw
    }
}

<#
.SYNOPSIS
    Sets WAC WinRM over HTTPS configuration.

.DESCRIPTION
    Sets WinRmOverHttps property in appsettings.json under %ProgramFiles%\WindowsAdminCenter.
    
.PARAMETER Mode
    Enablement or disablement of WinRM over HTTPS.

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, otherwise error.

.EXAMPLE
    Set-WACWinRmOverHttps -Enabled
#>
function Set-WACWinRmOverHttps {
    Param(
        [Parameter(Mandatory = $true)]
        [switch]$Enabled,
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    SetExitWithErrorCode $ExitWithErrorCode
    try {
        UpdateJsonField -Path (GetAppSettingsPath) -Sections "WindowsAdminCenter", "FeatureParameters", "Base", "WinRmOverHttps" -Value $Enabled
        Write-Log -Level INFO -ExitCode 0 -Message "Set-WACWinRmOverHttps: Successfully set WAC WinRM over HTTPS configuration."
        ExitWithErrorCode 0
    }
    catch {
        Write-Error $_
        Write-Log -Level ERROR -ExitCode 1 -Message "Set-WACWinRmOverHttps: Failed to set WAC WinRM over HTTPS configuration. Error: $_"
        ExitWithErrorCode 1
        throw
    }
}

<#
.SYNOPSIS
    Gets WAC WinRM over HTTPS setting.

.DESCRIPTION
    Gets WinRmOverHttps property in appsettings.json under %ProgramFiles%\WindowsAdminCenter.

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, otherwise error.

.EXAMPLE
    Get-WACWinRmOverHttps
#>
function Get-WACWinRmOverHttps {
    Param(
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    SetExitWithErrorCode $ExitWithErrorCode
    GetJsonField -Path (GetAppSettingsPath) -Sections "WindowsAdminCenter", "FeatureParameters", "Base", "WinRmOverHttps"
    Write-Log -Level INFO -ExitCode 0 -Message "Get-WACWinRmOverHttps: Successfully retrieved WAC WinRM over HTTPS settings."
    ExitWithErrorCode 0
}

<#
.SYNOPSIS
    Sets WAC software update mode.

.DESCRIPTION
    Sets the SoftwareUpdate property in appsettings.json under %ProgramFiles%\WindowsAdminCenter.
    
.PARAMETER Mode
    The mode of software update, such as Automatic, Manual, or Notification.

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, otherwise error.

.EXAMPLE
    Set-WACSoftwareUpdateMode -Mode Automatic
#>
function Set-WACSoftwareUpdateMode {
    Param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Automatic', 'Manual', 'Notification')]
        [string]$Mode,
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    SetExitWithErrorCode $ExitWithErrorCode
    try {
        UpdateJsonField -Path (GetAppSettingsPath) -Sections "WindowsAdminCenter", "System", "SoftwareUpdate" -Value $Mode
        Write-Log -Level INFO -ExitCode 0 -Message "Set-WACSoftwareUpdateMode: Successfully set WAC software update mode."
        ExitWithErrorCode 0
    }
    catch {
        Write-Error $_
        Write-Log -Level ERROR -ExitCode 1 -Message "Set-WACSoftwareUpdateMode: Failed to set WAC software update mode. Error: $_"
        ExitWithErrorCode 1
        throw
    }
}

<#
.SYNOPSIS
    Gets WAC software update mode.

.DESCRIPTION
    Gets the SoftwareUpdate property in appsettings.json under %ProgramFiles%\WindowsAdminCenter.

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, otherwise error.

.EXAMPLE
    Get-WACSoftwareUpdateMode
#>
function Get-WACSoftwareUpdateMode {
    Param(
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    SetExitWithErrorCode $ExitWithErrorCode
    GetJsonField -Path (GetAppSettingsPath) -Sections "WindowsAdminCenter", "System", "SoftwareUpdate"
    Write-Log -Level INFO -ExitCode 0 -Message "Get-WACSoftwareUpdateMode: Successfully retrieved WAC software update mode."
    ExitWithErrorCode 0
}

<#
.SYNOPSIS
    Sets WAC telemetry privacy mode.

.DESCRIPTION
    Sets the TelemetryPrivacy property in appsettings.json under %ProgramFiles%\WindowsAdminCenter.
    
.PARAMETER Mode
    The mode of telemetry privacy. Can be set to required or optional.

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, otherwise error.

.EXAMPLE
    Set-WACTelemetryPrivacy -Mode Required
#>
function Set-WACTelemetryPrivacy {
    Param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Required', 'Optional')]
        [string]$Mode,
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    SetExitWithErrorCode $ExitWithErrorCode
    try {
        UpdateJsonField -Path (GetAppSettingsPath) -Sections "WindowsAdminCenter", "System", "TelemetryPrivacy" -Value $Mode
        Write-Log -Level INFO -ExitCode 0 -Message "Set-WACTelemetryPrivacy: Successfully set WAC telemetry privacy mode."
        ExitWithErrorCode 0
    }
    catch {
        Write-Error $_
        Write-Log -Level ERROR -ExitCode 1 -Message "Set-WACTelemetryPrivacy: Failed to set WAC telemetry privacy mode. Error: $_"
        ExitWithErrorCode 1
        throw
    }
}

<#
.SYNOPSIS
    Gets WAC telemetry privacy mode.

.DESCRIPTION
    Gets the TelemetryPrivacy property in appsettings.json under %ProgramFiles%\WindowsAdminCenter.

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, otherwise error.

.EXAMPLE
    Get-WACTelemetryPrivacy
#>
function Get-WACTelemetryPrivacy {
    Param(
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    SetExitWithErrorCode $ExitWithErrorCode
    GetJsonField -Path (GetAppSettingsPath) -Sections "WindowsAdminCenter", "System", "TelemetryPrivacy"
    Write-Log -Level INFO -ExitCode 0 -Message "Get-WACTelemetryPrivacy: Successfully retrieved WAC telemetry privacy mode."
    ExitWithErrorCode 0
}

<#
.SYNOPSIS
    Sets WAC runtime mode.

.DESCRIPTION
    Sets the RuntimeMode property in appsettings.json under %ProgramFiles%\WindowsAdminCenter.

.PARAMETER Mode
    The mode of runtime, such as AzureExtension, Desktop, NonStandardService, or Service.

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, otherwise error.

.EXAMPLE
    Set-WACRuntimeMode -Mode AzureExtension
#>
function Set-WACRuntimeMode {
    Param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('AzureExtension', 'Desktop', 'NonStandardService', 'Service')]
        [string]$Mode,
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    SetExitWithErrorCode $ExitWithErrorCode
    try {
        UpdateJsonField -Path (GetAppSettingsPath) -Sections "WindowsAdminCenter", "System", "RuntimeMode" -Value $Mode
        Write-Log -Level INFO -ExitCode 0 -Message "Set-WACRuntimeMode: Successfully set WAC runtime mode."
        ExitWithErrorCode 0
    }
    catch {
        Write-Error $_
        Write-Log -Level ERROR -ExitCode 1 -Message "Set-WACRuntimeMode: Failed to set WAC runtime mode. Error: $_"
        ExitWithErrorCode 1
        throw
    }
}

<#
.SYNOPSIS
    Sets WAC CSP frame ancestors.

.DESCRIPTION
    Sets the CSPFrameAncestors property in appsettings.json under %ProgramFiles%\WindowsAdminCenter.

.PARAMETER CSPFrameAncestors
    The CSP frame ancestors.

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, otherwise error.

.EXAMPLE
    Set-WACCSPFrameAncestors -CSPFrameAncestors @("https://www.contoso.com", "https://www.fabrikam.com")
#>
function Set-WACCSPFrameAncestors {
    Param(
        [Parameter(Mandatory = $true)]
        [string[]]$CSPFrameAncestors,
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    SetExitWithErrorCode $ExitWithErrorCode
    try {
        UpdateJsonField -Path (GetAppSettingsPath) -Sections "WindowsAdminCenter", "Http", "CSPFrameAncestors" -Value $CSPFrameAncestors
        Write-Log -Level INFO -ExitCode 0 -Message "Set-WACCSPFrameAncestors: Successfully set WAC CSP frame ancestors."
        ExitWithErrorCode 0
    }
    catch {
        Write-Error $_
        Write-Log -Level ERROR -ExitCode 1 -Message "Set-WACCSPFrameAncestors: Failed to set WAC CSP frame ancestors. Error: $_"
        ExitWithErrorCode 1
        throw
    }
}

<#
.SYNOPSIS
    Gets WAC CSP frame ancestors.

.DESCRIPTION
    Gets the CSPFrameAncestors property in appsettings.json under %ProgramFiles%\WindowsAdminCenter.

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, otherwise error.

.EXAMPLE
    Get-WACCSPFrameAncestors
#>
function Get-WACCSPFrameAncestors {
    Param(
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    SetExitWithErrorCode $ExitWithErrorCode
    GetJsonField -Path (GetAppSettingsPath) -Sections "WindowsAdminCenter", "Http", "CSPFrameAncestors"
    Write-Log -Level INFO -ExitCode 0 -Message "Get-WACCSPFrameAncestors: Successfully retrieved WAC CSP frame ancestors."
    ExitWithErrorCode 0
}

<#
.SYNOPSIS
    Sets WAC CORS sites.

.DESCRIPTION
    Sets the CorsSites property in appsettings.json under %ProgramFiles%\WindowsAdminCenter.

.PARAMETER CorsSites
    The CORS sites.

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, otherwise error.

.EXAMPLE
    Set-WACCorsSites -CorsSites @("https://www.contoso.com", "https://www.fabrikam.com")
#>
function Set-WACCorsSites {
    Param(
        [Parameter(Mandatory = $true)]
        [string[]]$CorsSites,
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    SetExitWithErrorCode $ExitWithErrorCode
    try {
        UpdateJsonField -Path (GetAppSettingsPath) -Sections "WindowsAdminCenter", "Http", "CorsSites" -Value $CorsSites
        Write-Log -Level INFO -ExitCode 0 -Message "Set-WACCorsSites: Successfully set WAC CORS sites."
        ExitWithErrorCode 0
    }
    catch {
        Write-Error $_
        Write-Log -Level ERROR -ExitCode 1 -Message "Set-WACCorsSites: Failed to set WAC CORS sites. Error: $_"
        ExitWithErrorCode 1
        throw
    }
}

<#
.SYNOPSIS
    Gets WAC CORS sites.

.DESCRIPTION
    Gets the CorsSites property in appsettings.json under %ProgramFiles%\WindowsAdminCenter.

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, otherwise error.

.EXAMPLE
    Get-WACCorsSites
#>
function Get-WACCorsSites {
    Param(
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    SetExitWithErrorCode $ExitWithErrorCode
    GetJsonField -Path (GetAppSettingsPath) -Sections "WindowsAdminCenter", "Http", "CorsSites"
    Write-Log -Level INFO -ExitCode 0 -Message "Get-WACCorsSites: Successfully retrieved WAC CORS sites."
    ExitWithErrorCode 0
}

<#
.SYNOPSIS
    Sets WAC login mode.

.DESCRIPTION
    Sets the TokenAuthenticationMode property in appsettings.json under %ProgramFiles%\WindowsAdminCenter.

.PARAMETER Mode
    The mode of login, such as FormLogin, WindowsAuthentication, or AadSso.

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, otherwise error.

.EXAMPLE
    Set-WACLoginMode -Mode FormLogin
#>
function Set-WACLoginMode {
    Param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('FormLogin', 'WindowsAuthentication', 'AadSso')]
        [string]$Mode,
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    SetExitWithErrorCode $ExitWithErrorCode
    try {
        UpdateJsonField -Path (GetAppSettingsPath) -Sections "WindowsAdminCenter", "System", "TokenAuthenticationMode" -Value $Mode
        Write-Log -Level INFO -ExitCode 0 -Message "Set-WACLoginMode: Successfully set WAC login mode."
        ExitWithErrorCode 0
    }
    catch {
        Write-Error $_
        Write-Log -Level ERROR -ExitCode 1 -Message "Set-WACLoginMode: Failed to set WAC login mode. Error: $_"
        ExitWithErrorCode 1
        throw
    }
}

<#
.SYNOPSIS
    Gets WAC login mode.

.DESCRIPTION
    Gets the TokenAuthenticationMode property in appsettings.json under %ProgramFiles%\WindowsAdminCenter.

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, otherwise error.

.EXAMPLE
    Get-WACLoginMode
#>
function Get-WACLoginMode {
    Param(
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    SetExitWithErrorCode $ExitWithErrorCode
    GetJsonField -Path (GetAppSettingsPath) -Sections "WindowsAdminCenter", "System", "TokenAuthenticationMode"
    Write-Log -Level INFO -ExitCode 0 -Message "Get-WACLoginMode: Successfully retrieved WAC login mode."
    ExitWithErrorCode 0
}


<#
.SYNOPSIS
    Sets WAC HTTPS port range and service port numbers.

.DESCRIPTION
    Modifies the Url property in appsettings.json under %ProgramFiles%\WindowsAdminCenter to use the specified WacPort
    and sets the ServicePortRange property in appsettings.json to the values of ServicePortRangeStart and ServicePortRangeEnd.
    Throws an error if the provided port range is invalid.

.PARAMETER WacPort
    The port number of HTTPS for opening WAC in the browser.

.PARAMETER ServicePortRangeStart
    The start port number of HTTPS port range for internal WAC services.

.PARAMETER ServicePortRangeEnd
    The end port number of HTTPS port range for internal WAC services.

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, otherwise error.

.EXAMPLE
    Set-WACHttpsPorts -WacPort 443 -ServicePortRangeStart 444 -ServicePortRangeEnd 446
#>
function Set-WACHttpsPorts {
    Param(
        [Parameter(Mandatory = $true)]
        [int]$WacPort,
        [int]$ServicePortRangeStart,
        [int]$ServicePortRangeEnd,
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    SetExitWithErrorCode $ExitWithErrorCode
    try {
        UpdateJsonField -Path (GetAppSettingsPath) -Sections "Kestrel", "Endpoints", "WindowsAdminCenter", "Url" -Value "https://*:$WacPort"
        if($ServicePortRangeStart -and $ServicePortRangeEnd) {
            if($ServicePortRangeStart -ge $ServicePortRangeEnd) {
                Write-Error "Failed to set WAC HTTPS ports. Error: ServicePortRangeStart must be less than ServicePortRangeEnd."
                $errorMessage = "Set-WACHttpsPorts: Failed to set WAC HTTPS ports. Error: ServicePortRangeStart must be less than ServicePortRangeEnd."
                Write-Log -Level ERROR -ExitCode 1 -Message $errorMessage
                ExitWithErrorCode 1
                throw $errorMessage
            }
            if($ServicePortRangeStart -le $WacPort -and $WacPort -le $ServicePortRangeEnd) {
                Write-Error "Failed to set WAC HTTPS ports. Error: WacPort must be outside of ServicePortRangeStart and ServicePortRangeEnd."
                $errorMessage = "Set-WACHttpsPorts: Failed to set WAC HTTPS ports. Error: WacPort must be outside of ServicePortRangeStart and ServicePortRangeEnd."
                Write-Log -Level ERROR -ExitCode 1 -Message $errorMessage
                ExitWithErrorCode 1
                throw $errorMessage
            }
            if(($ServicePortRangeEnd - $ServicePortRangeStart) -lt 2) {
                Write-Error "Failed to set WAC HTTPS ports. Error: Port range size must be greater than 3."
                $errorMessage = "Set-WACHttpsPorts: Failed to set WAC HTTPS ports. Error: Port range size must be greater than 3."
                Write-Log -Level ERROR -ExitCode 1 -Message $errorMessage
                ExitWithErrorCode 1
                throw $errorMessage
            }
            if(($ServicePortRangeStart -eq $WacPort) -or ($ServicePortRangeEnd -eq $WacPort)) {
                Write-Error "Failed to set WAC HTTPS ports. Error: ServicePortRangeStart and ServicePortRangeEnd must be different from WacPort."
                $errorMessage = "Set-WACHttpsPorts: Failed to set WAC HTTPS ports. Error: ServicePortRangeStart and ServicePortRangeEnd must be different from WacPort."
                Write-Log -Level ERROR -ExitCode 1 -Message $errorMessage
                ExitWithErrorCode 1
                throw $errorMessage
            }
        }
        if($ServicePortRangeStart) {
            if($ServicePortRangeStart -eq $WacPort) {
                Write-Error "Failed to set WAC HTTPS ports. Error: ServicePortRangeStart must be different from WacPort."
                $errorMessage = "Set-WACHttpsPorts: Failed to set WAC HTTPS ports. Error: ServicePortRangeStart must be different from WacPort."
                Write-Log -Level ERROR -ExitCode 1 -Message $errorMessage
                ExitWithErrorCode 1
                throw $errorMessage
            }
            UpdateJsonField -Path (GetAppSettingsPath) -Sections "WindowsAdminCenter", "ServicePortRange", "Start" -Value $ServicePortRangeStart
            # Set WinREST and WinStream ports
            UpdateJsonField -Path (GetAppSettingsPath) -Sections "WindowsAdminCenter", "Services", 0,  "Endpoint" -Value "https://localhost:$ServicePortRangeStart"
            UpdateJsonField -Path (GetAppSettingsPath) -Sections "WindowsAdminCenter", "Services", 1, "Endpoint" -Value "https://localhost:$($ServicePortRangeStart + 1)"
        }
        if($ServicePortRangeEnd) {
            if($ServicePortRangeEnd -eq $WacPort) {
                Write-Error "Failed to set WAC HTTPS ports. Error: ServicePortRangeEnd must be different from WacPort."
                $errorMessage = "Set-WACHttpsPorts: Failed to set WAC HTTPS ports. Error: ServicePortRangeEnd must be different from WacPort."
                Write-Log -Level ERROR -ExitCode 1 -Message $errorMessage
                ExitWithErrorCode 1
                throw $errorMessage
            }
            UpdateJsonField -Path (GetAppSettingsPath) -Sections "WindowsAdminCenter", "ServicePortRange", "End" -Value $ServicePortRangeEnd
        }
        Write-Log -Level INFO -ExitCode 0 -Message "Set-WACHttpsPorts: Successfully set WAC HTTPS ports."
        ExitWithErrorCode 0
    }
    catch {
        Write-Error $_
        Write-Log -Level ERROR -ExitCode 1 -Message "Set-WACHttpsPorts: Failed to set WAC HTTPS ports. Error: $_"
        ExitWithErrorCode 1
        throw
    }
}

<#
.SYNOPSIS
    Gets WAC HTTPS Core service port and port range start and end for other services (e.g. WinREST and WinStream).

.DESCRIPTION
    Gets the WacPort from the Url property in appsettings.json under %ProgramFiles%\WindowsAdminCenter
    and gets the Start and End values of the ServicePortRange property in appsettings.json.

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, otherwise error.

.EXAMPLE
    Get-WACHttpsPorts
#>
function Get-WACHttpsPorts {
    Param(
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    SetExitWithErrorCode $ExitWithErrorCode
    (GetJsonField -Path  (GetAppSettingsPath) -Sections "Kestrel", "Endpoints", "WindowsAdminCenter", "Url").Split(":")[-1]
    GetJsonField -Path  (GetAppSettingsPath) -Sections "WindowsAdminCenter", "ServicePortRange", "Start"
    GetJsonField -Path  (GetAppSettingsPath) -Sections "WindowsAdminCenter", "ServicePortRange", "End"
    Write-Log -Level INFO -ExitCode 0 -Message "Get-WACHttpsPorts: Successfully retrieved WAC HTTPS ports."
    ExitWithErrorCode 0
}

<#
.SYNOPSIS
    Sets WAC certificate subject name when using Form Login. The certificate must be identifiable by the subject name.

.DESCRIPTION
    Sets the Subject property of the Certificate property in appsettings.json under %ProgramFiles%\WindowsAdminCenter to the given subject name, or that of the certificiate identified by the given thumbprint.
    If neither the subject name or thumbprint parameters are provided, the self-signed certificate subject name will be used.

.PARAMETER SubjectName
    The subject name of the certificate.

.PARAMETER Thumbprint
    The thumbprint of the certificate.

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, otherwise error.

.EXAMPLE
    Set-WACSubjectName

.EXAMPLE
    Set-WACSubjectName -SubjectName "CN=contoso.com"

.EXAMPLE
    Set-WACSubjectName -SubjectName "contoso.com"

.EXAMPLE
    Set-WACSubjectName -Thumbprint "1234567890abcdef1234567890abcdef12345678"
#>
function Set-WACSubjectName {
    Param(
        [Parameter(Mandatory = $false)]
        [string]$SubjectName,
        [Parameter(Mandatory = $false)]
        [string]$Thumbprint,
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    SetExitWithErrorCode $ExitWithErrorCode
    try {
        if ([System.String]::IsNullOrWhiteSpace($SubjectName) -and [System.String]::IsNullOrWhiteSpace($Thumbprint)) {
            $SubjectName = $ConstSSLCertificateSubjectName;
        }

        if (-not [System.String]::IsNullOrWhiteSpace($Thumbprint)) {
            $cert = Get-Item Cert:\LocalMachine\My\$Thumbprint
            $SubjectName = $cert.Subject

            if ($SubjectName.StartsWith("CN=")) {
                $SubjectName = ($SubjectName -split "=")[1]
            }

            $SubjectName = ($SubjectName -split ", ")[0]
        }

        UpdateJsonField -Path  (GetAppSettingsPath) -Sections "Kestrel", "Endpoints", "WindowsAdminCenter", "Certificate", "Subject" -Value $SubjectName
        Write-Log -Level INFO -ExitCode 0 -Message "Set-WACSubjectName: Successfully set WAC certificate subject name."
        ExitWithErrorCode 0
    }
    catch {
        Write-Error $_
        Write-Log -Level ERROR -ExitCode 1 -Message "Set-WACSubjectName: Failed to set WAC certificate subject name. Error: $_"
        ExitWithErrorCode 1
        throw
    }
}

<#
.SYNOPSIS
    Gets WAC certificate subject name when using Form Login. The certificate must be identifiable by the subject name.

.DESCRIPTION
    Gets the value of the Subject property under the Certificate property in appsettings.json under %ProgramFiles%\WindowsAdminCenter.

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, otherwise error.

.EXAMPLE
    Get-WACSubjectName
#>
function Get-WACSubjectName {
    Param(
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    SetExitWithErrorCode $ExitWithErrorCode
    GetJsonField -Path (GetAppSettingsPath) -Sections "Kestrel", "Endpoints", "WindowsAdminCenter", "Certificate", "Subject"
    Write-Log -Level INFO -ExitCode 0 -Message "Get-WACSubjectName: Successfully retrieved WAC certificate subject name."
    ExitWithErrorCode 0
}

<#
.SYNOPSIS
    Sets WAC certificate access control list.

.DESCRIPTION
    Modifies the access control list of the certificate identified by the given subject name to grant full control permissions to the Network Service account.
    If no subject name is provided, the subject name from the appsettings.json file under %ProgramFiles%\WindowsAdminCenter will be used.

.PARAMETER SubjectName
    The subject name of the certificate.

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, otherwise error.

.EXAMPLE
    Set-WACCertificateAcl

.EXAMPLE
    Set-WACCertificateAcl -SubjectName "CN=contoso.com"

.EXAMPLE
    Set-WACCertificateAcl -SubjectName "contoso.com"
#>
function Set-WACCertificateAcl {
    Param(
        [Parameter(Mandatory = $false)]
        [string]$SubjectName,
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    SetExitWithErrorCode $ExitWithErrorCode
    try {
        if ([System.string]::IsNullOrWhiteSpace($SubjectName)) {
            $SubjectName = GetJsonField -Path (GetAppSettingsPath) -Sections "Kestrel", "Endpoints", "WindowsAdminCenter", "Certificate", "Subject"
        }

        if (-not $SubjectName.StartsWith("CN=")) {
            $SubjectName = "CN=$SubjectName"
        }

        $cert = Get-ChildItem Cert:LocalMachine\My\* | Where-Object {($_.Subject -split ", ")[0] -eq $SubjectName}
        if ($cert -is [array] -and $cert.Count -gt 0) {
            $cert = $cert[0]
        }

        $keyName = $cert.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName
        $machineKeyPath = [IO.Path]::Combine($ConstMachineKeyRootPath, $keyName)

        if (($null -ne $keyName) -and (Test-Path -Path $machineKeyPath)) {
            $acl = Get-Acl -Path $machineKeyPath
            $networkServiceSid = New-Object System.Security.Principal.SecurityIdentifier -ArgumentList $ConstNetworkServiceSid
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule $networkServiceSid,$ConstFullControlPermissions,allow
            $acl.AddAccessRule($rule)

            Set-Acl -Path $machineKeyPath -AclObject $acl
            Write-Log -Level INFO -ExitCode 0 -Message "Set-WACCertificateAcl: Successfully set WAC certificate access control list."
        }
        else {
            Write-Log -Level INFO -ExitCode 0 -Message "Set-WACCertificateAcl: Unable to find machine key path for certificate. Skipping setting access control list."
        }

        ExitWithErrorCode 0
    }
    catch {
        Write-Error $_
        Write-Log -Level ERROR -ExitCode 1 -Message "Set-WACCertificateAcl: Failed to set WAC certificate access control list. Error: $_"
        ExitWithErrorCode 1
        throw
    }
}

<#
.SYNOPSIS
    Gets the firewall rule of Windows Admin Center external endpoint.

.DESCRIPTION
    Gets the firewall rule of Windows Admin Center external endpoint.

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, otherwise error.

.EXAMPLE
    Get-WACFirewallRule
#>
function Get-WACFirewallRule {
    Param(
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    SetExitWithErrorCode $ExitWithErrorCode
    try {
        $policy = New-Object -ComObject HNetCfg.FwPolicy2
        foreach ($rule in $policy.Rules) {
            if ($rule.Name -ieq $ConstInboundOpenException) {
                $rule
                Write-Log -Level INFO -ExitCode 0 -Message "Get-WACFirewallRule: Successfully retrieved WAC firewall rule."
                ExitWithErrorCode 0
                return
            }
        }
    }
    catch {
        Write-Error $_
        Write-Log -Level ERROR -ExitCode 1 -Message "Get-WACFirewallRule: Failed to get WAC firewall rule. Error: $_"
        ExitWithErrorCode 1
        throw
    }

    Write-Log -Level INFO -ExitCode 0 -Message "Get-WACFirewallRule: WAC firewall rule does not exist."
    ExitWithErrorCode 0
}

<#
.SYNOPSIS
    Removes the firewall rule of Windows Admin Center.

.DESCRIPTION
    Removes the firewall rule of Windows Admin Center, if it exits.

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, otherwise error.

.EXAMPLE
    Unregister-WACFirewallRule
#>
function Unregister-WACFirewallRule {
    Param(
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    SetExitWithErrorCode $ExitWithErrorCode
    try {
        $policy = New-Object -ComObject HNetCfg.FwPolicy2
        $remove = $null
        foreach ($rule in $policy.Rules) {
            if ($rule.Name -ieq $ConstInboundOpenException) {
                $remove = $rule
                break;
            }
        }

        if ($null -ne $remove) {
            $policy.Rules.Remove($remove.Name);
        }
    }
    catch {
        Write-Error $_
        Write-Log -Level ERROR -ExitCode 1 -Message "Unregister-WACFirewallRule: Failed to remove WAC firewall rule. Error: $_"
        ExitWithErrorCode 1
        throw
    }

    Write-Log -Level INFO -ExitCode 0 -Message "Unregister-WACFirewallRule: Successfully removed WAC firewall rule."
    ExitWithErrorCode 0
}

<#
.SYNOPSIS
    Creates new firewall rule for Windows Admin Center.

.DESCRIPTION
    Creates new firewall rule for Windows Admin Center to enable remote access to WAC from the browser.

.PARAMETER Port
    The port number of HTTPS connection. Default port number is 6600.

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, otherwise error.

.EXAMPLE
    Register-WACFirewallRule

.EXAMPLE
    Register-WACFirewallRule -Port 6600
#>
function Register-WACFirewallRule {
    Param(
        [Parameter(Mandatory = $false)]
        [int]$Port = $ConstDefaultPort,
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    # https://learn.microsoft.com/en-us/windows/win32/api/icftypes/ne-icftypes-net_fw_action
    $NET_FW_ACTION_ALLOW = 1
    # https://learn.microsoft.com/en-us/windows/win32/api/icftypes/ne-icftypes-net_fw_ip_protocol
    $NET_FW_IP_PROTOCOL_TCP = [int]6
    # https://learn.microsoft.com/en-us/windows/win32/api/icftypes/ne-icftypes-net_fw_profile_type2
    # Private | Domain | Public
    $NET_FW_PROFILE2_ALL = 7
    
    try {
        Unregister-WACFirewallRule -ExitWithErrorCode:$false
        SetExitWithErrorCode $ExitWithErrorCode
        $rule = New-Object -ComObject HNetCfg.FwRule
        $rule.Name = $ConstInboundOpenException
        $rule.Enabled = $true
        $rule.Action = $NET_FW_ACTION_ALLOW
        $rule.Protocol = $NET_FW_IP_PROTOCOL_TCP
        $rule.LocalPorts = $Port.ToString()
        $rule.Profiles = $NET_FW_PROFILE2_ALL
        $policy = New-Object -ComObject HNetCfg.FwPolicy2
        $policy.Rules.Add($rule)
    }
    catch {
        Write-Error $_
        Write-Log -Level ERROR -ExitCode 1 -Message "Register-WACFirewallRule: Failed to create WAC firewall rule. Error: $_"
        ExitWithErrorCode 1
        throw
    }

    Write-Log -Level INFO -ExitCode 0 -Message "Register-WACFirewallRule: Successfully created WAC firewall rule."
    ExitWithErrorCode 0
}

<#
.SYNOPSIS
    Sets WAC WinRM Trusted Hosts mode.

.DESCRIPTION
    Sets WinRM TrustedHosts property to '*' when TrustAll is specified, otherwise sets TrustedHosts property to empty.

.PARAMETER TrustAll
    Make any hosts trusted when using WinRM protocols, such as PowerShell remoting and CIM session.

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, otherwise error.

.EXAMPLE
    Set-WACWinRmTrustedHosts -TrustAll

.EXAMPLE
    Set-WACWinRmTrustedHosts
#>
function Set-WACWinRmTrustedHosts {
    Param(
        [switch]$TrustAll,
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    SetExitWithErrorCode $ExitWithErrorCode
    if ($TrustAll) {
        Invoke-WACWinCommand -Command $ConstWinRmCommand -Parameters "set", "winrm/config/client", "@{TrustedHosts=""*""}"
        Write-Log -Level INFO -ExitCode 0 -Message "Set-WACWinRmTrustedHosts: Successfully set TrustedHosts to *."
        ExitWithErrorCode 0
        return
    }

    Invoke-WACWinCommand -Command $ConstWinRmCommand -Parameters "set", "winrm/config/client", "@{TrustedHosts=""""}"
    Write-Log -Level INFO -ExitCode 0 -Message "Set-WACWinRmTrustedHosts: Successfully set TrustedHosts to empty."
    ExitWithErrorCode 0
}

<#
.SYNOPSIS
    Gets WAC WinRM Trusted Hosts settings.

.DESCRIPTION
    Gets the WinRM client configuration including TrustedHosts property.

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, otherwise error.

.EXAMPLE
    Get-WACWinRmTrustedHosts
#>
function Get-WACWinRmTrustedHosts {
    Param(
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    SetExitWithErrorCode $ExitWithErrorCode
    Invoke-WACWinCommand -Command $ConstWinRmCommand -Parameters "get", "winrm/config/client"
    Write-Log -Level INFO -ExitCode 0 -Message "Get-WACWinRmTrustedHosts: Successfully got TrustedHosts settings."
    ExitWithErrorCode 0
}

<#
.SYNOPSIS
    Gets Local CredSSP configuration instance.

.DESCRIPTION
    Gets the PowerShell session configuration instance for Local CredSSP.

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, otherwise error.

.EXAMPLE
    Get-WACLocalCredSSP
#>
function Get-WACLocalCredSSP {
    Param(
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    try {
        Get-PSSessionConfiguration -Name $ConstCredSspName -ErrorAction Stop
    }
    catch {
        Write-Error $_
        Write-Log -Level ERROR -ExitCode 1 -Message "Get-WACLocalCredSSP: Failed to get WAC local CredSSP configuration instance. Error: $_"
        ExitWithErrorCode 1
        throw
    }

    Write-Log -Level INFO -ExitCode 0 -Message "Get-WACLocalCredSSP: Successfully got WAC local CredSSP configuration instance."
    ExitWithErrorCode 0
}

<#
.SYNOPSIS
    Unregisters Local CredSSP configuration instance.

.DESCRIPTION
    Unregisters the PowerShell session configuration instance for Local CredSSP.

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, otherwise error.

.EXAMPLE
    Unregister-WACLocalCredSSP
#>
function Unregister-WACLocalCredSSP {
    Param(
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    try {
        $configuration = Get-PSSessionConfiguration -Name $ConstCredSspName
        Unregister-PSSessionConfiguration -Name $configuration.Name
        $group = Get-LocalGroup -Name $ConstCredSspGroupName -ErrorAction SilentlyContinue
        if ($group) {
            Remove-LocalGroup -Name $ConstCredSspGroupName
        }

        if (Test-Path -Path $ConstCredSspFolderPath) {
            Remove-Item -Path $ConstCredSspFolderPath -Recurse -Force -WarningAction SilentlyContinue -ErrorAction Stop | Out-Null
        }

        if (Test-Path -Path $ConstPolicyFolderPath) {
            Remove-Item -Path $ConstPolicyFolderPath -Recurse -Force -WarningAction SilentlyContinue -ErrorAction Stop | Out-Null
        }
    }
    catch {
        Write-Error $_
        Write-Log -Level ERROR -ExitCode 1 -Message "Unregister-WACLocalCredSSP: Failed to unregister WAC local CredSSP configuration instance. Error: $_"
        ExitWithErrorCode 1
        throw
    }

    Write-Log -Level INFO -ExitCode 0 -Message "Unregister-WACLocalCredSSP: Successfully unregistered WAC local CredSSP configuration instance."
    ExitWithErrorCode 0
}

<#
.SYNOPSIS
    Registers Local CredSSP configuration instance.

.DESCRIPTION
    Unregisters old PowerShell session configuration instance for CredSSP if it exists, and then registers new instance.

.PARAMETER NoWinRmServiceRestart
    Don't restart WinRM service after the configuration.

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, otherwise error.

.EXAMPLE
    Register-WACLocalCredSSP

.EXAMPLE
    Register-WACLocalCredSSP -NoWinRmServiceRestart
#>
function Register-WACLocalCredSSP {
    Param(
        [Parameter(Mandatory = $false)]
        [switch]$NoWinRmServiceRestart,
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    try {
        # 0 create local group
        $group = Get-LocalGroup -Name $ConstCredSspGroupName -ErrorAction SilentlyContinue
        if ($group) {
            Remove-LocalGroup -Name $ConstCredSspGroupName
        }

        New-LocalGroup -Name $ConstCredSspGroupName -Description $ConstCredSspGroupDescription
        $user = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $userName = $user.Name
        Add-LocalGroupMember -Group $ConstCredSspGroupName -Member $userName

        # 1 remove old one if exists.
        $existing = Get-PSSessionConfiguration -Name $ConstCredSspName -ErrorAction SilentlyContinue
        if ($existing) {
            Unregister-PSSessionConfiguration -Name $ConstCredSspName -Force -WarningAction SilentlyContinue -ErrorAction Stop
        }

        # 2 configure CredSSP script module (Msft.Sme.Shell).
        # 2a refresh CredSSP folder content.
        if (Test-Path -Path $ConstCredSspFolderPath) {
            Remove-Item -Path $ConstCredSspFolderPath -Recurse -Force -WarningAction SilentlyContinue -ErrorAction Stop | Out-Null
        }
        
        New-Item -Path $ConstCredSspFolderPath -ItemType Directory | Out-Null
        Copy-Item -Recurse -Path "$ConstShellModuleFolderPath\*"  -Destination $ConstCredSspFolderPath | Out-Null

        # 2b import the signer certificate(s) into the TrustedPublisher store.
        $moduleFiles = Get-ChildItem -Path $ConstCredSspFolderPath -Include @('*.psm1', '*.psd1') -Recurse
        $importedThumbprints = @{}
        foreach ($moduleFile in $moduleFiles) {
            $moduleAuthenticodeSignature = Get-AuthenticodeSignature -FilePath $moduleFile.FullName
            if ($moduleAuthenticodeSignature.Status -ne "Valid") {
                continue
            }

            if (-not $importedThumbprints.Contains($moduleAuthenticodeSignature.SignerCertificate.Thumbprint) -and
                -not (Test-Path -Path (Join-Path -Path 'Cert:\LocalMachine\TrustedPublisher' -ChildPath $moduleAuthenticodeSignature.SignerCertificate.Thumbprint))) {
                $store = New-Object System.Security.Cryptography.X509Certificates.X509Store -ArgumentList ([System.Security.Cryptography.X509Certificates.StoreName]::TrustedPublisher),
                    ([System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
                $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite -bor [System.Security.Cryptography.X509Certificates.OpenFlags]::MaxAllowed)
                $store.Add($moduleAuthenticodeSignature.SignerCertificate)
                $store.Close()
            }
        }
        if ($null -ne $store) {
            $store.Dispose()
            $store = $null
        }
    
        # 3 creates role capabilities settings file (.psrc).
        $allowed = @(
            "$ConstShellModuleName\Enable-WACSHCredSSPClientRole",
            "$ConstShellModuleName\Get-WACSHCredSSPClientRole",
            "$ConstShellModuleName\Disable-WACSHCredSspClientRole",
            "$ConstShellModuleName\Test-WACSHCredSsp",
            "$ConstShellModuleName\Get-WACSHCredSspClientConfigurationOnGateway",
            "$ConstShellModuleName\Get-WACSHCredSspManagedServer"
        )
        $contentPsrc = "@{GUID='$((New-Guid).Guid)';VisibleFunctions='$([System.string]::Join("','", $allowed))';}";
        if (Test-Path -Path $ConstPolicyFolderPath) {
            Remove-Item -Path $ConstPolicyFolderPath -Recurse -Force -WarningAction SilentlyContinue -ErrorAction Stop | Out-Null
        }

        New-Item -Path $ConstPolicyFolderPath -ItemType Directory | Out-Null
        New-Item -Path (Join-Path $ConstPolicyFolderPath $ConstRoleCapabilities) -ItemType Directory | Out-Null
        $contentPsrc | Set-Content -Path (Join-Path $ConstPolicyFolderPath "$($ConstRoleCapabilities)\$($ConstCredSspAdmin).psrc") -Force

        # 4 define endpoint settings.
        $psscPath = [System.IO.Path]::GetTempFileName().Replace(".tmp", ".pssc")
        $machineName = [System.Environment]::MachineName
        $networkService = (new-object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::NetworkServiceSid, $null)).Translate([System.Security.Principal.NTAccount])
        $configuration = @{
            Path                 = $psscPath
            SessionType          = 'RestrictedRemoteServer'
            SchemaVersion        = '2.0.0.0'
            GUID                 = (new-Guid).Guid
            RunAsVirtualAccount  = $True
            RoleDefinitions      = @{
                $userName                             = @{RoleCapabilities = $ConstCredSspRoleName }
                $networkService.Value                 = @{RoleCapabilities = $ConstCredSspRoleName }
                "$machineName\$ConstCredSspGroupName" = @{RoleCapabilities = $ConstCredSspRoleName }
            }
            EnvironmentVariables = @{PSModulePath = "$ConstCredSspFolderPath;$($Env:PSModulePath)" }
            ExecutionPolicy      = 'AllSigned'
        }

        # 4a Create the configuration file
        New-PSSessionConfigurationFile @configuration
        Register-PSSessionConfiguration -Name $ConstCredSspName -Path $psscPath -NoServiceRestart:$NoWinRmServiceRestart -Force -WarningAction SilentlyContinue -ErrorAction Stop

        # 4b Enable PowerShell logging on the system
        $basePath = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
        if (-not (Test-Path $basePath)) {
            $null = New-Item $basePath -Force
        }

        Set-ItemProperty $basePath -Name EnableScriptBlockLogging -Value "1" -ErrorAction Stop
    }
    catch {
        Write-Error $_
        Write-Log -Level ERROR -ExitCode 1 -Message "Register-WACLocalCredSSP: Failed to register CredSSP session configuration."
        ExitWithErrorCode 1
        throw
    }

    Write-Log -Level INFO -ExitCode 0 -Message "Register-WACLocalCredSSP: Successfully registered CredSSP session configuration."
    ExitWithErrorCode 0
}

<#
.SYNOPSIS
    Imports previously installed extensions into WAC.

.DESCRIPTION
    Imports previously installed extensions into WAC from the extensions folder.

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, otherwise error.

.EXAMPLE
    Import-WACExistingExtensions
#>
function Import-WACExistingExtensions {
    Param(
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    SetExitWithErrorCode $ExitWithErrorCode

    $extensionsConfigFilePath = Join-Path $ConstExtensionsFolderPath $ConstExtensionsConfigFileName
    if (-not (Test-Path -Path $extensionsConfigFilePath)) {
        # Not an upgrade installation, no previously installed extensions to import.
        Write-Log -Level INFO -ExitCode 0 -Message "Import-WACExistingExtensions: No previously installed extensions to import."
        ExitWithErrorCode 0
        return
    }

    try {
        Add-Type -Path (Join-Path $ConstServiceFolderPath $ConstNuGetVersioningDllName)
        
        $defaultExtensions = GetPreInstalledExtensions
        $extensionsConfig = Get-Content -Path $extensionsConfigFilePath -Raw | ConvertFrom-Json
        $extensionsConfig.IsPreinstallDataPopulated = $false
        $removeList = @()

        foreach ($configuredExtension in $extensionsConfig.Extensions) {
            $configuredExtensionPath = Join-Path $ConstExtensionsFolderPath "$($configuredExtension.Id).$($configuredExtension.Version)"
            $configuredExtensionPathExists = Test-Path -Path $configuredExtensionPath
            if (-not $configuredExtensionPathExists) {
                $removeList += $configuredExtension
                continue
            }

            if ($configuredExtension.IsPreInstalled) {
                # Remove pre-installed extensions that shipped with the older gateway.
                if ($configuredExtensionPathExists) {
                    Remove-Item $configuredExtensionPath -Recurse
                }

                $removeList += $configuredExtension
                continue
            }

            if (($configuredExtension.Status -As [ExtensionStatus]) -eq [ExtensionStatus]::Installed) {
                if ($null -ne $defaultExtensions[$configuredExtension.Id] -and
                    [NuGet.Versioning.NuGetVersion]$configuredExtension.Version -le [NuGet.Versioning.NuGetVersion]$defaultExtensions[$configuredExtension.Id]) {
                    # Gateway ships with a newer version of the extension, remove the older version from the configuration.
                    $removeList += $configuredExtension
                    continue
                }

                # The extension installed from the feed is newer, remove the extension version that ships with the gateway.
                $configuredExtensionUxDirectory = Join-Path $ConstModulesFolderPath $configuredExtension.Id
                if (Test-Path -Path $configuredExtensionUxDirectory) {
                    Remove-Item $configuredExtensionUxDirectory -Recurse
                }
            }

            ConfigureCachedExtensions $configuredExtensionPath $configuredExtension
        }

        UpdateShellManifest
        RemoveRange $removeList $extensionsConfigFilePath $extensionsConfig
    }
    catch {
        Write-Error $_
        Write-Log -Level ERROR -ExitCode 1 -Message "Import-WACExistingExtensions: Failed to import previously installed extensions. Exception: $_"
        ExitWithErrorCode 1
        throw
    }

    Write-Log -Level INFO -ExitCode 0 -Message "Import-WACExistingExtensions: Successfully imported previously installed extensions."
    ExitWithErrorCode 0
}

<#
.SYNOPSIS
    Imports previously installed plugins into WAC.

.DESCRIPTION
    Imports previously installed plugins into WAC from the plugins folder.

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, otherwise error.

.EXAMPLE
    Import-WACExistingPlugins
#>
function Import-WACExistingPlugins {
    Param(
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    SetExitWithErrorCode $ExitWithErrorCode

    if (Test-Path -Path $ConstPluginsFolderPath) {
        $pluginDirectories = Get-ChildItem -Path $ConstPluginsFolderPath -Directory
    }

    if ($null -eq $pluginDirectories -or $pluginDirectories.Count -eq 0) {
        # Not an upgrade installation or no previously installed plugins to import.
        Write-Log -Level INFO -ExitCode 0 -Message "Import-WACExistingPlugins: No previously installed plugins to import."
        ExitWithErrorCode 0
        return
    }

    try {
        $appSettings = Get-Content -Path (GetAppSettingsPath) -Raw | ConvertFrom-Json
        $services = [System.Collections.Generic.List[PSCustomObject]]$appSettings.WindowsAdminCenter.Services
        $features = [System.Collections.Generic.List[PSCustomObject]]$appSettings.WindowsAdminCenter.Features

        foreach ($directory in $pluginDirectories) {
            $settingsFilePath = Join-Path $directory.FullName $ConstExtensionSettingsFileName
            $settings = Get-Content -Path $settingsFilePath -Raw | ConvertFrom-Json
            if ($services.FindIndex({ param($service) $service.Name -eq $settings.Service.Name }) -eq -1) {
                $services.Add($settings.Service)
            }

            $settings.Feature.FullPath = $directory.FullName
            $features.Add($settings.Feature)
        }

        $port = [int]$appSettings.WindowsAdminCenter.ServicePortRange.Start
        $portRangeEnd = [int]$appSettings.WindowsAdminCenter.ServicePortRange.End
        foreach ($service in $services) {
            # TODO: Can we assign services ports based on availablility? Aka without user knowledge of the port the service will use
            if ($port -ge $portRangeEnd) {
                throw "No available ports remaining in given port range."
            }
            $serviceEndpointSegments = $service.Endpoint -Split ':'
            $endpointHostName = "$($serviceEndpointSegments[0]):$($serviceEndpointSegments[1])"
            $service.Endpoint = "$($endpointHostName):$port"
            $port++
        }

        $appSettings.WindowsAdminCenter.Services = $services.ToArray()
        $appSettings.WindowsAdminCenter.Features = $features.ToArray()
        $appSettings | ConvertTo-Json -Depth 100 | Set-Content -Path (GetAppSettingsPath) -ErrorAction Stop
    }
    catch {
        Write-Error $_
        Write-Log -Level ERROR -ExitCode 1 -Message "Import-WACExistingPlugins: Failed to import previously installed plugins. Exception: $_"
        ExitWithErrorCode 1
        throw
    }

    Write-Log -Level INFO -ExitCode 0 -Message "Import-WACExistingPlugins: Successfully imported previously installed plugins."
    ExitWithErrorCode 0
}

<#
.SYNOPSIS
    Creates database for WAC if it doesn't exist and performs necessary migrations.

.DESCRIPTION
    Runs .NET Entity Framework bundle executable to create WAC database and/or perform necessary migrations.

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, otherwise error.

.EXAMPLE
    Initialize-WACDatabase
#>
function Initialize-WACDatabase {
    Param(
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    SetExitWithErrorCode $ExitWithErrorCode

    $efBundlePath = Join-Path $ConstServiceFolderPath $ConstEntityFrameworkBundleFileName

    Invoke-WACWinCommand -Command $efBundlePath -Parameters @()        

    Write-Log -Level INFO -ExitCode 0 -Message "Initialize-WACDatabase: Successfully initialized database."
    ExitWithErrorCode 0
}

<#
.SYNOPSIS
    Checks if the WAC installation failed.

.DESCRIPTION
    Checks if the WAC installation failed by checking the configuration log file.

.PARAMETER LogFilePath
    The path to the configuration log file.

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, otherwise error.

.EXAMPLE
    Test-WACInstallationFailure -LogFilePath "C:\ProgramData\Windows Admin Center\Logs\Configuration.log"
#>
function Test-WACInstallationFailure {
    Param(
        [Parameter(Mandatory = $true)]
        [string]$LogFilePath,
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )
    SetExitWithErrorCode $ExitWithErrorCode
    $result = $False;
    foreach ($line in (Get-Content $LogFilePath)) {
        # Log format: "StampPart1 StampPart2 Level=Level ExitCode=ExitCode Message=Message"
        $exitCode = [int]$line.Split(" =")[5]
        $result = [int]($result -or $exitCode)
    }
    ExitWithErrorCode $result
}

<#
.SYNOPSIS
    Utility function to invoke a Windows command.
    (This command is Microsoft internal use only.)
    
.DESCRIPTION
    Invokes a Windows command and generates an exception if the command returns an error. Note: only for application commands. 

.PARAMETER Command
    The name of the command we want to invoke.

.PARAMETER Parameters
    The parameters we want to pass to the command.

.PARAMETER NoExit
    Don't exit even when it has an error to start the command.

.EXAMPLE
    Invoke-WACWinCommand "netsh" "http delete sslcert ipport=0.0.0.0:9999"
#>
function Invoke-WACWinCommand {
    Param(
        [string]$Command, 
        [string[]]$Parameters,
        [switch]$NoExit
    )

    try {
        Write-Verbose "$command $([System.String]::Join(" ", $Parameters))"
        $startInfo = New-Object System.Diagnostics.ProcessStartInfo
        $startInfo.FileName = $Command
        $startInfo.RedirectStandardError = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.UseShellExecute = $false
        $startInfo.Arguments = [System.String]::Join(" ", $Parameters)
        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $startInfo
    }
    catch {
        Write-Error $_
        if (-not $NoExit) {
            Write-Log -Level ERROR -ExitCode 1 -Message "$($Command): Failed to initialize process during Invoke-WACWinCommand. Error - $_"
            ExitWithErrorCode 1
            throw
        }
    }

    try {
        $process.Start() | Out-Null
    }
    catch {
        Write-Error $_
        if (-not $NoExit) {
            Write-Log -Level ERROR -ExitCode 1 -Message "$($Command): Failed to start process during Invoke-WACWinCommand. Error - $_"
            ExitWithErrorCode 1
            throw
        }
    }

    try {
        $process.WaitForExit() | Out-Null
        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()
        $output = $stdout + "`r`n" + $stderr
    } 
    catch {
        Write-Error $_
        if (-not $NoExit) {
            Write-Log -Level ERROR -ExitCode 1 -Message "$($Command): Failed to wait for process exit and capture output during Invoke-WACWinCommand. Error - $_"
            ExitWithErrorCode 1
            throw
        }
    }

    if ($process.ExitCode -ne 0) {
        Write-Error $_
        if (-not $NoExit) {
            Write-Log -Level ERROR -ExitCode $process.ExitCode -Message "$($Command): Failed during process execution started by Invoke-WACWinCommand. Process output - $output"
            ExitWithErrorCode $process.ExitCode
            throw $output
        }
    }

    # output all messages
    return $output
}

<#
.SYNOPSIS
    Gets SID of current user Windows identity.

.DESCRIPTION
    Gets SID of current user Windows identity.

.EXAMPLE
    Get-WACCurrentWindowsIdentitySID
#>
function Get-WACCurrentWindowsIdentitySID {
    return [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
}

<#
.SYNOPSIS
    Add user SID to DACL of WAC service's security descriptor.

.DESCRIPTION
    Add user SID to DACL of WAC service's security descriptor to allow it to operate service through launcher without elevation.

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, otherwise error.

.EXAMPLE
    Add-WACUserSIDToSecurityDescriptor -UserSID "S-1-5-21-3623811015-3361044348-30300820-1013"
#>
function Add-WACUserSIDToSecurityDescriptor {
    Param(
        [Parameter(Mandatory = $true)]
        [string]$UserSID,
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    SetExitWithErrorCode $ExitWithErrorCode

    try {
        $saclPrefix = "S:"
        $defaultSecurityDescriptor = (Invoke-WACWinCommand -Command $ConstServiceController -Parameters "sdshow", $ConstServiceName).Trim()
        $securityDescriptorParts = $defaultSecurityDescriptor -Split $saclPrefix
        $dacl = $securityDescriptorParts[0]
        $sacl = $securityDescriptorParts[1]

        $wacServiceSecurityDescriptor = "$dacl(A;;RPWPCR;;;$UserSID)$saclPrefix$sacl"

        Invoke-WACWinCommand -Command $ConstServiceController -Parameters "sdset", $ConstServiceName, $wacServiceSecurityDescriptor
    }
    catch {
        Write-Error $_
        Write-Log -Level ERROR -ExitCode 1 -Message "Add-WACUserSIDToSecurityDescriptor: Failed to set user SID to service secirity descriptor. $_"
        ExitWithErrorCode 1
        throw
    }

    Write-Log -Level INFO -ExitCode 0 -Message "Add-WACUserSIDToSecurityDescriptor: Successfully set user SID to service secirity descriptor."
    ExitWithErrorCode 0
}

<#
.SYNOPSIS
    Sets security descriptor on service to allow current user to operate through launcher without elevation.

.DESCRIPTION
    Adds current user SID to DACL of WAC service's security descriptor to allow it to operate service through launcher without elevation.

.PARAMETER ExitWithErrorCode
    Exit the script with the error code. 0 is success, otherwise error.

.EXAMPLE
    Set-WACServiceSecurityDescriptor
#>
function Set-WACServiceSecurityDescriptor {
    Param(
        [Parameter(Mandatory = $false)]
        [switch]$ExitWithErrorCode
    )

    SetExitWithErrorCode $ExitWithErrorCode

    try {
        $wacCurrentUserSID = Get-WACCurrentWindowsIdentitySID
        Add-WACUserSIDToSecurityDescriptor -UserSID $wacCurrentUserSID
    }
    catch {
        Write-Error $_
        Write-Log -Level ERROR -ExitCode 1 -Message "Set-WACServiceSecurityDescriptor: Failed to set security descriptor. $_"
        ExitWithErrorCode 1
        throw
    }

    Write-Log -Level INFO -ExitCode 0 -Message "Set-WACServiceSecurityDescriptor: Successfully set security descriptor."
    ExitWithErrorCode 0
}

# Two global variables are used to track down the exit code usage.
$global:_exitOnce = $false
$global:_exitCount = 0

function SetExitWithErrorCode($exitWithErrorCode) {
    $global:_exitWithErrorCode = $exitWithErrorCode
}

<#
.SYNOPSIS
    Tracks exit code when a command runs with ExitWithErrorCode switch parameter.
.DESCRIPTION
    "Exit" function is the only way to report the exit code of script when launched through the installer.
    However a script will be terminated when "Exit" function is called. And "Exit" will close current
    PowerShell interactive console as well. To control these behavior, SetExitWithErrorCode and ExitWithErrorCode
    are implemented.

    Every entry function must be defined with $ExitWithErrorCode optional parameter. It must reflect the value
    by calling "SetExitWithErrorCode $ExitWithErrorCode". This function applies tracking mode of exit code.
    The function must call "ExitWithErrorCode" function only once in the function lifetime.
    Exit code feature is not available if you call multiple function by external client like interactive
    session or calling by another script. The function must be called once and finish the script session.
#>
function ExitWithErrorCode($exitCode) {
    if ($global:_exitWithErrorCode) {
        $global:_exitCount++
        if ($global:_exitCount -gt 1) {
            Write-Warning "Are you exiting multiple times ($($global:_exitCount))?"
            Write-Warning "Exit code feature can be used only once after import this module"
            Write-Warning "Cannot use parameter -ExitWithErrorCode"
            Write-Warning "Exiting ... $exitCode"
        }

        if (-not $global:_exitOnce) {
            if ($exitCode -ne 0) {
                $global:_exitOnce = $true
            }

            Write-Verbose "Exit $exitCode"
            Exit $exitCode
        }
    }
}

<#
.SYNOPSIS
    Utility function to modify a JSON file.
    
.DESCRIPTION
    Updates a field in a JSON file to the given value. 

.PARAMETER Path
    The path to the JSON file to be updated.

.PARAMETER Sections
    An array indicating the field to be modified.
    Uses the name of the sections in top-down order and a number indicating the desired index for an array. (Please see example below.)

.PARAMETER Value
    The value to be set to the field.

.EXAMPLE
    UpdateJsonField -Path (GetAppSettingsPath) -Sections "WindowsAdminCenter", "Services", 0,  "Endpoint" -Value "https://localhost:$ServicePortRangeStart"
#>
function UpdateJsonField {
    Param(
        [string]$Path, 
        [object[]]$Sections,
        [object]$Value
    )

    $jsonFile = Get-Content -Path $Path -Raw -ErrorAction Stop | ConvertFrom-Json
    $jsonField = $jsonFile
    
    $sectionCount = $Sections.Count
    $sectionIndex = 0
    foreach ($section in $Sections) {
        $sectionIndex++

        if ($section -is [int]) {
            $jsonField = $jsonField[$section]
            continue
        }

        if ($sectionIndex -eq $sectionCount) {
            $jsonField.$section = $Value
            break
        }

        $jsonField = $jsonField.$section
    }

    $jsonFile | ConvertTo-Json -Depth 100 | Set-Content -Path $Path -ErrorAction Stop
}

<#
.SYNOPSIS
    Utility function to read a JSON file.
    
.DESCRIPTION
    Reads a field in a JSON file. 

.PARAMETER Path
    The path to the JSON file to be read.

.PARAMETER Sections
    An array indicating the field to be read.
    Uses the name of the sections in top-down order and a number indicating the desired index for an array. (Please see example below.)

.EXAMPLE
    GetJsonField -Path (GetAppSettingsPath) -Sections "WindowsAdminCenter", "System", "InstallDate"
#>
function GetJsonField {
    Param(
        [string]$Path, 
        [object[]]$Sections
    )

    $jsonField = Get-Content -Path $Path -Raw -ErrorAction Stop | ConvertFrom-Json

    foreach ($section in $Sections) {
        if ($section -is [int]) {
            $jsonField = $jsonField[$section]
            continue
        }
        $jsonField = $jsonField.$section
    }

    return $jsonField
}

function GetAppSettingsPath {
    return [System.IO.Path]::GetFullPath((Join-Path -Path $ConstServiceFolderPath -ChildPath $ConstAppConfigJsonName))
}

function GetPreInstalledExtensions {
    $preInstalledExtensions = @{}
    if (Test-Path -Path $ConstModulesFolderPath) {
        foreach ($directory in Get-ChildItem -Path $ConstModulesFolderPath -Directory) {
            $extensionId = $directory.Name
            $manifestPath = Join-Path $directory.FullName $ConstExtensionManifestFileName
            $manifest = Get-Content -Path $manifestPath -Raw | ConvertFrom-Json
            $version = [NuGet.Versioning.NuGetVersion]$manifest.version

            $preInstalledExtensions.Add($extensionId, $version)
        }
    }

    return $preInstalledExtensions
}

function ConfigureCachedExtensions {
    Param(
        [string]$ConfiguredExtensionPath,
        [PSCustomObject]$ConfiguredExtension
    )

    $extensionUxPath = Join-Path $ConfiguredExtensionPath $ConstExtensionUxFolderName
    $extensionManifestPath = Join-Path $extensionUxPath $ConstExtensionManifestFileName
    if (-not (Test-Path -Path $extensionManifestPath)) {
        return
    }

    $manifest = Get-Content -Path $extensionManifestPath -Raw | ConvertFrom-Json
    $moduleName = $manifest.name
    if ($null -eq $manifest.version) {
        # Force update to extensions.config version information when manifest.json doesn't include version property.
        UpdateJsonField -Path $extensionManifestPath -Sections "version" -Value $ConfiguredExtension.Version
    }

    $extensionIndexPath = Join-Path $extensionUxPath $ConstExtensionIndexFileName
    if (Test-Path -Path $extensionIndexPath) {
        $indexContent = Get-Content -Path $extensionIndexPath -Raw
        $indexContent.Replace("<base href=`"/`">", "<base href=`"/modules/$($moduleName)/`">") | Set-Content -Path $extensionIndexPath
    }
    
    $extensionModulePath = Join-Path $ConstModulesFolderPath $ConfiguredExtension.Id
    if (Test-Path -Path $extensionModulePath) {
        Remove-Item -Path $extensionModulePath -Recurse
        New-Item -Path $extensionModulePath -ItemType Directory
    }

    Copy-Item -Path $extensionUxPath -Destination $extensionModulePath -Recurse -Force -ErrorAction Stop

    $extensionPluginPath = Join-Path $ConstPluginsFolderPath "$($ConfiguredExtension.Id).$($ConfiguredExtension.Version)"
    if (Test-Path -Path $extensionPluginPath) {
        Remove-Item -Path $extensionPluginPath -Recurse
    }

    $extensionGatewayPath = Join-Path $ConfiguredExtensionPath $ConstExtensionGatewayFolderName
    if (Test-Path -Path $extensionGatewayPath) {
        New-Item -Path $extensionPluginPath -ItemType Directory -ErrorAction SilentlyContinue
        Copy-Item -Path $extensionGatewayPath -Destination $extensionPluginPath -Recurse -Force -ErrorAction Stop
    }
}

function UpdateShellManifest {
    $shellManifestPath = Join-Path $ConstUxFolderPath $ConstExtensionManifestFileName
    $shellManifest = Get-Content -Path $shellManifestPath -Raw | ConvertFrom-Json
    $shellManifest.modules = @()
    foreach ($directory in Get-ChildItem -Path $ConstModulesFolderPath -Directory) {
        $extensionManifestPath = Join-Path $directory.FullName $ConstExtensionManifestFileName
        $extensionManifest = Get-Content -Path $extensionManifestPath -Raw | ConvertFrom-Json
        $shellManifest.modules += $extensionManifest
    }

    $shellManifest | ConvertTo-Json -Depth 100 | Set-Content -Path $shellManifestPath -ErrorAction Stop
}

function RemoveRange {
    Param(
        [System.Collections.Generic.List[PSCustomObject]]$RemoveList,
        [string]$ExtensionsConfigFilePath,
        [PSCustomObject]$ExtensionsConfig
    )
    $extensions = [System.Collections.Generic.List[PSCustomObject]]$ExtensionsConfig.Extensions

    foreach ($extension in $RemoveList) {
        $matchingExtensionIndex = $extensions.FindIndex({ param($x) $x.Id -eq $extension.Id -and $x.Version -eq $extension.Version })
        if ($matchingExtensionIndex -ne -1) {
            $extensions.RemoveAt($matchingExtensionIndex)
        }
    }

    $ExtensionsConfig.Extensions = $extensions.ToArray()
    $ExtensionsConfig | ConvertTo-Json -Depth 100 | Set-Content -Path $ExtensionsConfigFilePath -ErrorAction Stop
}

function AssertEventLogExists {
    Param(
        [string]$EventLogName
    )
    return [System.Diagnostics.EventLog]::Exists($EventLogName)
}

function CreateEventSources {
    $sources = @("Core", "Launcher", "Updater", "AccountManagement")
    $sources += @(GetJsonField -Path  (GetAppSettingsPath) -Sections "WindowsAdminCenter", "Services", 0, "Name")
    $sources += @(GetJsonField -Path  (GetAppSettingsPath) -Sections "WindowsAdminCenter", "Services", 1, "Name")

    foreach ($source in $sources) {
        New-EventLog -Source $source -LogName $ConstEventLogName -ErrorAction Stop
    }
}

function Write-Log {
    Param(
        [Parameter(Mandatory = $True)]
        [ValidateSet("INFO", "WARN", "ERROR", "DEBUG")]
        [String]
        $Level,
        [Parameter(Mandatory = $True)]
        [string]
        $ExitCode,
        [Parameter(Mandatory = $True)]
        [string]
        $Message
    )

    $Stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
    $Line = "$Stamp Level=$Level ExitCode=$ExitCode Message=$Message"
    $LogFilePath = Join-Path $ConstLogFolderPath $ConstLogFileName

    if (Test-Path -Path $ConstLogFolderPath) {
        Add-Content $LogFilePath -Value $Line
    }
}

# SIG # Begin signature block
# MIInvwYJKoZIhvcNAQcCoIInsDCCJ6wCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDFqYVcLzTB+ulP
# Ag6AY1Un0b4V3W4LUjcmGsTMpP8pDaCCDXYwggX0MIID3KADAgECAhMzAAADrzBA
# DkyjTQVBAAAAAAOvMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjMxMTE2MTkwOTAwWhcNMjQxMTE0MTkwOTAwWjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDOS8s1ra6f0YGtg0OhEaQa/t3Q+q1MEHhWJhqQVuO5amYXQpy8MDPNoJYk+FWA
# hePP5LxwcSge5aen+f5Q6WNPd6EDxGzotvVpNi5ve0H97S3F7C/axDfKxyNh21MG
# 0W8Sb0vxi/vorcLHOL9i+t2D6yvvDzLlEefUCbQV/zGCBjXGlYJcUj6RAzXyeNAN
# xSpKXAGd7Fh+ocGHPPphcD9LQTOJgG7Y7aYztHqBLJiQQ4eAgZNU4ac6+8LnEGAL
# go1ydC5BJEuJQjYKbNTy959HrKSu7LO3Ws0w8jw6pYdC1IMpdTkk2puTgY2PDNzB
# tLM4evG7FYer3WX+8t1UMYNTAgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQURxxxNPIEPGSO8kqz+bgCAQWGXsEw
# RQYDVR0RBD4wPKQ6MDgxHjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEW
# MBQGA1UEBRMNMjMwMDEyKzUwMTgyNjAfBgNVHSMEGDAWgBRIbmTlUAXTgqoXNzci
# tW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3JsMGEG
# CCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3J0
# MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBAISxFt/zR2frTFPB45Yd
# mhZpB2nNJoOoi+qlgcTlnO4QwlYN1w/vYwbDy/oFJolD5r6FMJd0RGcgEM8q9TgQ
# 2OC7gQEmhweVJ7yuKJlQBH7P7Pg5RiqgV3cSonJ+OM4kFHbP3gPLiyzssSQdRuPY
# 1mIWoGg9i7Y4ZC8ST7WhpSyc0pns2XsUe1XsIjaUcGu7zd7gg97eCUiLRdVklPmp
# XobH9CEAWakRUGNICYN2AgjhRTC4j3KJfqMkU04R6Toyh4/Toswm1uoDcGr5laYn
# TfcX3u5WnJqJLhuPe8Uj9kGAOcyo0O1mNwDa+LhFEzB6CB32+wfJMumfr6degvLT
# e8x55urQLeTjimBQgS49BSUkhFN7ois3cZyNpnrMca5AZaC7pLI72vuqSsSlLalG
# OcZmPHZGYJqZ0BacN274OZ80Q8B11iNokns9Od348bMb5Z4fihxaBWebl8kWEi2O
# PvQImOAeq3nt7UWJBzJYLAGEpfasaA3ZQgIcEXdD+uwo6ymMzDY6UamFOfYqYWXk
# ntxDGu7ngD2ugKUuccYKJJRiiz+LAUcj90BVcSHRLQop9N8zoALr/1sJuwPrVAtx
# HNEgSW+AKBqIxYWM4Ev32l6agSUAezLMbq5f3d8x9qzT031jMDT+sUAoCw0M5wVt
# CUQcqINPuYjbS1WgJyZIiEkBMIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkq
# hkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5
# IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEwOTA5WjB+MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQg
# Q29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+laUKq4BjgaBEm6f8MMHt03
# a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc6Whe0t+bU7IKLMOv2akr
# rnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4Ddato88tt8zpcoRb0Rrrg
# OGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+lD3v++MrWhAfTVYoonpy
# 4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nkkDstrjNYxbc+/jLTswM9
# sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6A4aN91/w0FK/jJSHvMAh
# dCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmdX4jiJV3TIUs+UsS1Vz8k
# A/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL5zmhD+kjSbwYuER8ReTB
# w3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zdsGbiwZeBe+3W7UvnSSmn
# Eyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3T8HhhUSJxAlMxdSlQy90
# lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS4NaIjAsCAwEAAaOCAe0w
# ggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRIbmTlUAXTgqoXNzcitW2o
# ynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYD
# VR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBDuRQFTuHqp8cx0SOJNDBa
# BgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2Ny
# bC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3JsMF4GCCsG
# AQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3J0MIGfBgNV
# HSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEFBQcCARYzaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1hcnljcHMuaHRtMEAGCCsG
# AQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkAYwB5AF8AcwB0AGEAdABl
# AG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn8oalmOBUeRou09h0ZyKb
# C5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7v0epo/Np22O/IjWll11l
# hJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0bpdS1HXeUOeLpZMlEPXh6
# I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/KmtYSWMfCWluWpiW5IP0
# wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvyCInWH8MyGOLwxS3OW560
# STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBpmLJZiWhub6e3dMNABQam
# ASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJihsMdYzaXht/a8/jyFqGa
# J+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYbBL7fQccOKO7eZS/sl/ah
# XJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbSoqKfenoi+kiVH6v7RyOA
# 9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sLgOppO6/8MO0ETI7f33Vt
# Y5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtXcVZOSEXAQsmbdlsKgEhr
# /Xmfwb1tbWrJUnMTDXpQzTGCGZ8wghmbAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAAOvMEAOTKNNBUEAAAAAA68wDQYJYIZIAWUDBAIB
# BQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEILWRYIDtzaDLQb1zoF7QJdzk
# +RplCNk+uSsoV8vYFVQZMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEAghR8aieqHLtzB+wt1kg8zarFyYiimClmMpNK7mAuojmcNWcrgV4L/wVk
# WaSvSfhJ5H726nEa3tpjQvpnjScwbDAHajkia5BrvODYk/AP0/LgI7obcidH+zQ3
# xhmUCSBbZx07fhC4BVbjX3R4Qt5RPiULlOnNk8VG7S0JxHG/X9XI4NSipMs9QT8R
# 0MBB4lpp9QlY9bhOFxzCaIS3rBalosA2JpyVQEldYYSMSrR8eAlIwtnH8dVfiBGV
# g8DA7ezLukqbspE3Xs0Fnr536dPcTXx11HquAgVvlKIvBC++IX81Q7OEs3F4cnBV
# I1ZZTP0MkMFkcnJWMnOVj/yYe74v2KGCFykwghclBgorBgEEAYI3AwMBMYIXFTCC
# FxEGCSqGSIb3DQEHAqCCFwIwghb+AgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFZBgsq
# hkiG9w0BCRABBKCCAUgEggFEMIIBQAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCD6ZWSc3Ni5np7CtrzemhrzduM9Plh0LzdJDif0mif33gIGZV3r58LE
# GBMyMDIzMTIxNTIzMDcwOS45MThaMASAAgH0oIHYpIHVMIHSMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJl
# bGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNO
# OjJBRDQtNEI5Mi1GQTAxMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBT
# ZXJ2aWNloIIReDCCBycwggUPoAMCAQICEzMAAAHenkielp8oRD0AAQAAAd4wDQYJ
# KoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjMx
# MDEyMTkwNzEyWhcNMjUwMTEwMTkwNzEyWjCB0jELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMkTWljcm9zb2Z0IElyZWxhbmQgT3Bl
# cmF0aW9ucyBMaW1pdGVkMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjoyQUQ0LTRC
# OTItRkEwMTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCC
# AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALSB9ByF9UIDhA6xFrOniw/x
# sDl8sSi9rOCOXSSO4VMQjnNGAo5VHx0iijMEMH9LY2SUIBkVQS0Ml6kR+TagkUPb
# aEpwjhQ1mprhRgJT/jlSnic42VDAo0en4JI6xnXoAoWoKySY8/ROIKdpphgI7OJb
# 4XHk1P3sX2pNZ32LDY1ktchK1/hWyPlblaXAHRu0E3ynvwrS8/bcorANO6Djuysy
# S9zUmr+w3H3AEvSgs2ReuLj2pkBcfW1UPCFudLd7IPZ2RC4odQcEPnY12jypYPnS
# 6yZAs0pLpq0KRFUyB1x6x6OU73sudiHON16mE0l6LLT9OmGo0S94Bxg3N/3aE6fU
# bnVoemVc7FkFLum8KkZcbQ7cOHSAWGJxdCvo5OtUtRdSqf85FklCXIIkg4sm7nM9
# TktUVfO0kp6kx7mysgD0Qrxx6/5oaqnwOTWLNzK+BCi1G7nUD1pteuXvQp8fE1Kp
# TjnG/1OJeehwKNNPjGt98V0BmogZTe3SxBkOeOQyLA++5Hyg/L68pe+DrZoZPXJa
# GU/iBiFmL+ul/Oi3d83zLAHlHQmH/VGNBfRwP+ixvqhyk/EebwuXVJY+rTyfbRfu
# h9n0AaMhhNxxg6tGKyZS4EAEiDxrF9mAZEy8e8rf6dlKIX5d3aQLo9fDda1ZTOw+
# XAcAvj2/N3DLVGZlHnHlAgMBAAGjggFJMIIBRTAdBgNVHQ4EFgQUazAmbxseaapg
# dxzK8Os+naPQEsgwHwYDVR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYD
# VR0fBFgwVjBUoFKgUIZOaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9j
# cmwvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwG
# CCsGAQUFBwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIw
# MjAxMCgxKS5jcnQwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcD
# CDAOBgNVHQ8BAf8EBAMCB4AwDQYJKoZIhvcNAQELBQADggIBAOKUwHsXDacGOvUI
# gs5HDgPs0LZ1qyHS6C6wfKlLaD36tZfbWt1x+GMiazSuy+GsxiVHzkhMW+FqK8gr
# uLQWN/sOCX+fGUgT9LT21cRIpcZj4/ZFIvwtkBcsCz1XEUsXYOSJUPitY7E8bbld
# mmhYZ29p+XQpIcsG/q+YjkqBW9mw0ru1MfxMTQs9MTDiD28gAVGrPA3NykiSChvd
# qS7VX+/LcEz9Ubzto/w28WA8HOCHqBTbDRHmiP7MIj+SQmI9VIayYsIGRjvelmNa
# 0OvbU9CJSz/NfMEgf2NHMZUYW8KqWEjIjPfHIKxWlNMYhuWfWRSHZCKyIANA0aJL
# 4soHQtzzZ2MnNfjYY851wHYjGgwUj/hlLRgQO5S30Zx78GqBKfylp25aOWJ/qPhC
# +DXM2gXajIXbl+jpGcVANwtFFujCJRdZbeH1R+Q41FjgBg4m3OTFDGot5DSuVkQg
# jku7pOVPtldE46QlDg/2WhPpTQxXH64sP1GfkAwUtt6rrZM/PCwRG6girYmnTRLL
# sicBhoYLh+EEFjVviXAGTk6pnu8jx/4WPWu0jsz7yFzg82/FMqCk9wK3LvyLAyDH
# N+FxbHAxtgwad7oLQPM0WGERdB1umPCIiYsSf/j79EqHdoNwQYROVm+ZX10RX3n6
# bRmAnskeNhi0wnVaeVogLMdGD+nqMIIHcTCCBVmgAwIBAgITMwAAABXF52ueAptJ
# mQAAAAAAFTANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNh
# dGUgQXV0aG9yaXR5IDIwMTAwHhcNMjEwOTMwMTgyMjI1WhcNMzAwOTMwMTgzMjI1
# WjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQD
# Ex1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDCCAiIwDQYJKoZIhvcNAQEB
# BQADggIPADCCAgoCggIBAOThpkzntHIhC3miy9ckeb0O1YLT/e6cBwfSqWxOdcjK
# NVf2AX9sSuDivbk+F2Az/1xPx2b3lVNxWuJ+Slr+uDZnhUYjDLWNE893MsAQGOhg
# fWpSg0S3po5GawcU88V29YZQ3MFEyHFcUTE3oAo4bo3t1w/YJlN8OWECesSq/XJp
# rx2rrPY2vjUmZNqYO7oaezOtgFt+jBAcnVL+tuhiJdxqD89d9P6OU8/W7IVWTe/d
# vI2k45GPsjksUZzpcGkNyjYtcI4xyDUoveO0hyTD4MmPfrVUj9z6BVWYbWg7mka9
# 7aSueik3rMvrg0XnRm7KMtXAhjBcTyziYrLNueKNiOSWrAFKu75xqRdbZ2De+JKR
# Hh09/SDPc31BmkZ1zcRfNN0Sidb9pSB9fvzZnkXftnIv231fgLrbqn427DZM9itu
# qBJR6L8FA6PRc6ZNN3SUHDSCD/AQ8rdHGO2n6Jl8P0zbr17C89XYcz1DTsEzOUyO
# ArxCaC4Q6oRRRuLRvWoYWmEBc8pnol7XKHYC4jMYctenIPDC+hIK12NvDMk2ZItb
# oKaDIV1fMHSRlJTYuVD5C4lh8zYGNRiER9vcG9H9stQcxWv2XFJRXRLbJbqvUAV6
# bMURHXLvjflSxIUXk8A8FdsaN8cIFRg/eKtFtvUeh17aj54WcmnGrnu3tz5q4i6t
# AgMBAAGjggHdMIIB2TASBgkrBgEEAYI3FQEEBQIDAQABMCMGCSsGAQQBgjcVAgQW
# BBQqp1L+ZMSavoKRPEY1Kc8Q/y8E7jAdBgNVHQ4EFgQUn6cVXQBeYl2D9OXSZacb
# UzUZ6XIwXAYDVR0gBFUwUzBRBgwrBgEEAYI3TIN9AQEwQTA/BggrBgEFBQcCARYz
# aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9Eb2NzL1JlcG9zaXRvcnku
# aHRtMBMGA1UdJQQMMAoGCCsGAQUFBwMIMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIA
# QwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFNX2
# VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwu
# bWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEw
# LTA2LTIzLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93
# d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYt
# MjMuY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQCdVX38Kq3hLB9nATEkW+Geckv8qW/q
# XBS2Pk5HZHixBpOXPTEztTnXwnE2P9pkbHzQdTltuw8x5MKP+2zRoZQYIu7pZmc6
# U03dmLq2HnjYNi6cqYJWAAOwBb6J6Gngugnue99qb74py27YP0h1AdkY3m2CDPVt
# I1TkeFN1JFe53Z/zjj3G82jfZfakVqr3lbYoVSfQJL1AoL8ZthISEV09J+BAljis
# 9/kpicO8F7BUhUKz/AyeixmJ5/ALaoHCgRlCGVJ1ijbCHcNhcy4sa3tuPywJeBTp
# kbKpW99Jo3QMvOyRgNI95ko+ZjtPu4b6MhrZlvSP9pEB9s7GdP32THJvEKt1MMU0
# sHrYUP4KWN1APMdUbZ1jdEgssU5HLcEUBHG/ZPkkvnNtyo4JvbMBV0lUZNlz138e
# W0QBjloZkWsNn6Qo3GcZKCS6OEuabvshVGtqRRFHqfG3rsjoiV5PndLQTHa1V1QJ
# sWkBRH58oWFsc/4Ku+xBZj1p/cvBQUl+fpO+y/g75LcVv7TOPqUxUYS8vwLBgqJ7
# Fx0ViY1w/ue10CgaiQuPNtq6TPmb/wrpNPgkNWcr4A245oyZ1uEi6vAnQj0llOZ0
# dFtq0Z4+7X6gMTN9vMvpe784cETRkPHIqzqKOghif9lwY1NNje6CbaUFEMFxBmoQ
# tB1VM1izoXBm8qGCAtQwggI9AgEBMIIBAKGB2KSB1TCB0jELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMkTWljcm9zb2Z0IElyZWxh
# bmQgT3BlcmF0aW9ucyBMaW1pdGVkMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjoy
# QUQ0LTRCOTItRkEwMTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2Vy
# dmljZaIjCgEBMAcGBSsOAwIaAxUAaKBSisy4y86pl8Xy22CJZExE2vOggYMwgYCk
# fjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQD
# Ex1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUFAAIF
# AOkmu/cwIhgPMjAyMzEyMTUxOTUwMTVaGA8yMDIzMTIxNjE5NTAxNVowdDA6Bgor
# BgEEAYRZCgQBMSwwKjAKAgUA6Sa79wIBADAHAgEAAgIZLDAHAgEAAgIRsDAKAgUA
# 6SgNdwIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAID
# B6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBAGmZBIWbVU+3kul+0QvX
# gUZCdsdc4e07eAuQTJXx0DSAaO8X7CcWzA0JG4FG/qS653wv0oFolBzVxtkA70Nl
# AbeIba9fZDdXpM7xP9offwEJKP8k7n/8qVhlf3R/Jyq870YZx5nNvF1B5FQU7yb8
# d9EifsLqyWVbe5wYDAXTk9kuMYIEDTCCBAkCAQEwgZMwfDELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgUENBIDIwMTACEzMAAAHenkielp8oRD0AAQAAAd4wDQYJYIZIAWUDBAIB
# BQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQx
# IgQgsRx6zOrBDbpOa3KG7dMq29HIQiD9glxZ/LsctfPOUDUwgfoGCyqGSIb3DQEJ
# EAIvMYHqMIHnMIHkMIG9BCCOPiOfDcFeEBBJAn/mC3MgrT5w/U2z81LYD44Hc34d
# ezCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# JjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAAB3p5I
# npafKEQ9AAEAAAHeMCIEIEGmf9Sdr/HXzEdjB+uoEx2FYuajqTHXiXbGMXAA8qvE
# MA0GCSqGSIb3DQEBCwUABIICAEVMt3KdnBRid9oMtPzlvzpMkaZhQNNQz+kKfAnK
# R67Vg1OjxIMTGl0XK9ulctnkCJn0dAJjDwNR1K2N5cip3xH86uP4j0eRURHnESA+
# a4gfrJ6N6W2qrKh/S/MUxLhlLtgJHRlu0OBI6U3KD1s+gm20fsnGM4ghDGpYEm7F
# N5fYUFz0s70x/DZE0oJ1WKqDd8Q8GLjwQU3MzJqYXYJbpxd9qImWpapmS9p5hr6P
# 88TqtlTBPFWE6HOcDDkFJUrL0zHiinEH2Q/MHAePS3FzbxXxr4NYx0qloq92+2JE
# eMeVwGjMXtke9/y3L9JUezyp7YBhr9oquHhThplFguDfMXaV9S6U+lvjW1loT3/U
# nPXhR0wF4bNn3uj0hHztCk0p3i5nVAKnDdCUyPpROCcKhfUkfzuIyKMgF3g6OAkd
# kbp+d66weUTVcoT56NkCJySh8pglb8I1ezMRjyOise7BvZlwmhRJS9QoupMJWmEg
# Z4TYhcYWQHpRURV+qqlf0hhiax/JWz+VUsA4CPcq1bwuQGURVODJqjFxc1NRP3oY
# Edd69ToLdAptP1Dk4xSHNefjCxzzvojbu5pmOsw93XHriLpM2BNU5DEW0pa7IkLy
# sqhbR8pv+Ifr1jVAdfOYtRHvongbCRFs4j6qOyTdET6aTlo9T1+f9FkIJv1WvcYH
# ARTP
# SIG # End signature block
