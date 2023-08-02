param([switch]$Elevated)

function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

if ((Test-Admin) -eq $false)  {
    if ($elevated) {
        # Tried to elevate, but it didn't work. Aborting.
    } else {
        Start-Process powershell.exe -Verb RunAs -ArgumentList ('-noprofile -noexit -file "{0}" -elevated' -f ($myinvocation.MyCommand.Definition))
    }
    exit
}

'Running with full privileges'


# Set the path of the blank screensaver
$screensaverPath = "C:\Windows\System32\scrnsave.scr" 

# Change the screensaver 
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "SCRNSAVE.EXE" /t REG_SZ /d $screensaverPath /f 


# Set a timeout of 15 minutes to display the screensaver
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop" /v ScreenSaveTimeOut /t REG_SZ /d 900 /f 

# Enable the screensaver
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop" /v ScreenSaveActive /t REG_SZ /d 1 /f 

# Require the password for the screensaver
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop" /v ScreenSaveUsePassword /t REG_SZ /d 1 /f 

# Confirm before emptying the recycle bin 
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v ConfirmFileDelete /t REG_DWORD /d 1 /f

# Show file extensions
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0

# Show hidden icons 

# Prevent entering sleep mode when closing the laptop lid
powercfg -setacvalueindex SCHEME_CURRENT SUB_BUTTONS LIDACTION 0

# Disable the timeout for sleep mode when the laptop lid is closed
powercfg -setacvalueindex SCHEME_CURRENT SUB_VIDEO VIDEOIDLE 0

# Apply the changes 
powercfg -SetActive SCHEME_CURRENT


# Stop the service
Stop-Service -Name "WSearch" -Force

# Set the startup of the Windows Indexer to "Disabled"
Set-Service -Name "WSearch" -StartupType "Disabled"

# Force Windows Update
wuauclt.exe /updatenow
