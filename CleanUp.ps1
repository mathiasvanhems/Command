if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }

function DisplayMenu {
    Clear-Host
    Write-Host @"
+=================================================================================================================================+
|  Windows Clean-Up - MENU                                                                                                        | 
+=================================================================================================================================+
|                                                                                                                                 |
|    1) Nettoyer l'image Windows avec DISM (peut être très long: ScanHealth, RestoreHealth, StartComponentCleanup & SPSuperSeded) |
|    2) Nettoyer `"PeerDistRepub branch cache`"                                                                                     |
|    3) Nettoyer le cache CCM (C:\Windows\ccmcache)                                                                               |
|    4) Nettoyer et relancer WindowsUpdate (C:\Windows\SoftwareDistribution\Download)                                             |
|    5) Nettoyer les memory dumps windows (C:\Windows\LiveKernelReports)                                                          |
|    6) Nettoyer les journaux windows (C:\Windows\Logs)                                                                           |
|    7) Nettoyer le cache WindowsInstaller (C:\Windows\Installer\`$PatchCache`$)                                                    |
|    8) Réparer les compteurs de performances windows (C:\Windows\system32 et C:\Windows\syswow64)                                |
|    98) Executer tout sauf DISM                                                                                                  |
|    99) Executer tout                                                                                                            |
|    0) Sortie                                                                                                                    |
+=================================================================================================================================+

"@

    $MENU = Read-Host "OPTION"
    Switch ($MENU)
    {
        1 {
            DISMCleanUp
            Write-Host "Opération terminée" -ForegroundColor DarkBlue -BackgroundColor white
            Read-Host -Prompt "Appuyez sur entrée pour revenir au menu"
            DisplayMenu
        }
        2 {
            PeerDistRepubCleanUp
            Write-Host "Opération terminée" -ForegroundColor DarkBlue -BackgroundColor white
            Read-Host -Prompt "Appuyez sur entrée pour revenir au menu"
            DisplayMenu
        }
        3 {
            CCMCleanUp
            Write-Host "Opération terminée" -ForegroundColor DarkBlue -BackgroundColor white
            Read-Host -Prompt "Appuyez sur entrée pour revenir au menu"
            DisplayMenu
        }
        4 {
            WindowsUpdateCleanUp
            Write-Host "Opération terminée" -ForegroundColor DarkBlue -BackgroundColor white
            Read-Host -Prompt "Appuyez sur entrée pour revenir au menu"
            DisplayMenu
        }
        5 {
            KernelMemoryDumpsCleanup
            Write-Host "Opération terminée" -ForegroundColor DarkBlue -BackgroundColor white
            Read-Host -Prompt "Appuyez sur entrée pour revenir au menu"
            DisplayMenu
        }
        6 {
            WindowsLogsCleanUp
            Write-Host "Opération terminée" -ForegroundColor DarkBlue -BackgroundColor white
            Read-Host -Prompt "Appuyez sur entrée pour revenir au menu"
            DisplayMenu
        }
        7 {
            WindowsInstallerBaselineCacheCleanUp
            Write-Host "Opération terminée" -ForegroundColor DarkBlue -BackgroundColor white
            Read-Host -Prompt "Appuyez sur entrée pour revenir au menu"
            DisplayMenu
        }
        8 {
            RepairPerfCounters
            Write-Host "Opération terminée" -ForegroundColor DarkBlue -BackgroundColor white
            Read-Host -Prompt "Appuyez sur entrée pour revenir au menu"
            DisplayMenu
        }
        98 {
            PeerDistRepubCleanUp
            CCMCleanUp
            WindowsUpdateCleanUp
            KernelMemoryDumpsCleanup
            WindowsLogsCleanUp
            WindowsInstallerBaselineCacheCleanUp
            RepairPerfCounters
            Write-Host "Opération terminée" -ForegroundColor DarkBlue -BackgroundColor white
            Read-Host -Prompt "Appuyez sur entrée pour revenir au menu"
            DisplayMenu
        }
        99 {
            DISMCleanUp
            PeerDistRepubCleanUp
            CCMCleanUp
            WindowsUpdateCleanUp
            KernelMemoryDumpsCleanup
            WindowsLogsCleanUp
            WindowsInstallerBaselineCacheCleanUp
            RepairPerfCounters
            Write-Host "Opération terminée" -ForegroundColor DarkBlue -BackgroundColor white
            Read-Host -Prompt "Appuyez sur entrée pour revenir au menu"
            DisplayMenu
        }
        0 {
            break
        }
        default {
            #DEFAULT OPTION
            Write-Host "Option not available"
            Start-Sleep -Seconds 2
            DisplayMenu
        }
    }
}

function DISMCleanUp{
    Write-Host "ScanHealth de l'image windows... soyez patient..." -ForegroundColor DarkBlue -BackgroundColor white
    dism.exe /online /Cleanup-Image /Scanhealth
    Write-Host "RestoreHealth de l'image windows... soyez patient..." -ForegroundColor DarkBlue -BackgroundColor white
    dism.exe /online /Cleanup-Image /RestoreHealth
    Write-Host "SPSuperseded de l'image windows... soyez patient..." -ForegroundColor DarkBlue -BackgroundColor white
    dism.exe /online /Cleanup-Image /SPSuperseded
    Write-Host "StartComponentCleanup de l'image windows... soyez patient..." -ForegroundColor DarkBlue -BackgroundColor white
    dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase
}

function PeerDistRepubCleanUp {
    Write-Host "Néttoyer `"PeerDistRepub branch cache`"" -ForegroundColor DarkBlue -BackgroundColor white
    netsh branchcache flush
}
function CCMCleanUp{
    Write-Host "CCM cache cleanup" -ForegroundColor DarkBlue -BackgroundColor white
    [__comobject]$CCMComObject = New-Object -ComObject 'UIResource.UIResourceMgr'
    $CacheInfo = $CCMComObject.GetCacheInfo().GetCacheElements()
    ForEach ($CacheItem in $CacheInfo) {
        $null = $CCMComObject.GetCacheInfo().DeleteCacheElement([string]$($CacheItem.CacheElementID))
    }
}
function WindowsUpdateCleanUp{
    Write-Host "Windows Update Cleanup" -ForegroundColor DarkBlue -BackgroundColor white
    net stop wuauserv
    net stop bits
    Remove-Item "C:\Windows\SoftwareDistribution\Download" -Force -Recurse
    net start bits
    net start wuauserv
    UsoClient.exe refreshsettings
    UsoClient.exe startinteractivescan
}
function KernelMemoryDumpsCleanup{
    Write-Host "Clean kernel memory dumps" -ForegroundColor DarkBlue -BackgroundColor white
    if(Test-Path C:\Windows\LiveKernelReports)
    {
	    Remove-Item "C:\Windows\LiveKernelReports" -Force -Recurse
    }
}

function WindowsLogsCleanUp{
    Write-Host "Clean windows logs" -ForegroundColor DarkBlue -BackgroundColor white
    net stop TrustedInstaller  
    net stop WaaSMedicSvc
    net stop wuauserv
    takeown /f "C:\Windows\Logs\waasmedic"
    takeown /f "C:\Windows\Logs\waasmedic\*.*"
    icacls "C:\Windows\Logs\waasmedic" /grant Administrateurs:f
    icacls "C:\Windows\Logs\waasmedic\*.*" /grant Administrateurs:f
    Remove-Item "C:\Windows\Logs" -Force -Recurse
    net start wuauserv
    net start WaaSMedicSvc
    net start TrustedInstaller
}
function WindowsInstallerBaselineCacheCleanUp{
    Write-Host "Clean windows installer baseline cache" -ForegroundColor DarkBlue -BackgroundColor white
    net stop msiserver
    net stop TrustedInstaller
    if(!(Test-Path  "HKLM:\Software\Policies\Microsoft\Windows"))
    {
	    New-Item –Path "HKLM:\Software\Policies\Microsoft\Windows" –Name Installer
    }
    Set-Itemproperty -path 'HKLM:\Software\Policies\Microsoft\Windows\Installer' -Name 'MaxPatchCacheSize' -value 0
    if(Test-Path "C:\Windows\Installer\`$PatchCache`$")
    {
	    Remove-Item "C:\Windows\Installer\`$PatchCache`$" -Force -Recurse
    }
    net Start msiserver /Y
    net start TrustedInstaller
    net stop msiserver
    net stop TrustedInstaller
    Set-Itemproperty -path 'HKLM:\Software\Policies\Microsoft\Windows\Installer' -Name 'MaxPatchCacheSize' -value 10
    net Start msiserver /Y
    net start TrustedInstaller
}
function RepairPerfCounters{
    Write-Host "Repair perfcounters" -ForegroundColor DarkBlue -BackgroundColor white
    cd "C:\Windows\system32"
    lodctr /R
    cd "C:\Windows\syswow64"
    lodctr /R
    winmgmt.exe /RESYNCPERF
    # For some reason, needs to be done twice.
    cd "C:\Windows\system32"
    lodctr /R
    cd "C:\Windows\syswow64"
    lodctr /R
    winmgmt.exe /RESYNCPERF
}
DisplayMenu