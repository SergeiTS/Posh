Import-Module posh-git
Import-Module oh-my-posh
Set-Theme Paradox
Set-Alias -name icmp -value Test-Connection
Set-Alias -name c -value Clear-Host
Set-Alias -name getadc -value Get-ADComputer
Set-Alias -name getadu -value Get-ADUser
Set-Alias -name testp -value Test-Path
Set-PSReadLineOption -PredictionSource History
#Import-Module ActiveDirectory
#Set-Location d:\PowerShell
#Prompt
#Get-Command -Module Microsoft*,Cim*,PS*,ISE | Get-Random | Get-Help -ShowWindow
#Get-Random -input (Get-Help about*) | Get-Help -ShowWindow
#Set-ExecutionPolicy bypass -Scope CurrentUser
#$autodir = "d:\SCRIPTS\PowerShell\AUTOLOAD\" 
#Get-ChildItem "${autodir}\*.ps1" | ForEach-Object {.$_} 
#$output = "Scripts in " + $autodir  + " loaded"
#Write-Host $output
###############################################################################################################################################################################################################################
Function Get-LoggedUserLocal {
    param (
        [parameter (Mandatory = $true)]
        [string]$ComputerName
    )
    $opt = New-CimSessionOption -Protocol DCOM 
    $opt.Timeout = '00:01:00'
    $sess = New-CimSession -ComputerName $ComputerName -SessionOption $opt
    ""  
    (Get-CimInstance -CimSession $sess -ClassName Win32_ComputerSystem).UserName
    ""
}
###############################################################################################################################################################################################################################
Function Get-LoggedUserExplorer 
{
    param (
            [parameter (Mandatory=$true)]
            [string]$ComputerName
          )
          $opt = New-CimSessionOption -Protocol DCOM 
          $opt.Timeout = '00:01:00'
          $sess = New-CimSession -ComputerName $ComputerName -SessionOption $opt
          $processes = Get-CimInstance -CimSession $sess -ClassName Win32_Process -Filter "name = 'explorer.exe'"   
          $owner = Invoke-CimMethod -InputObject $processes -MethodName GetOwner
          ""
          $processes | ForEach-Object {'{0}\{1}' -f  $owner.Domain, $owner.User} | Sort-Object -Unique
          ""
}
###############################################################################################################################################################################################################################
Function Get-LoggedUserFull  
{
    param (
            [parameter (Mandatory=$true)]
            [string]$ComputerName
          )
        $opt = New-CimSessionOption -Protocol DCOM 
        $opt.Timeout = '00:01:00'
        $sess = New-CimSession -ComputerName $ComputerName -SessionOption $opt      
        $login = ((Get-CimInstance -CimSession $sess -ClassName Win32_ComputerSystem).UserName) -creplace "DOMAIN\\"
        Get-aduser -Identity $login -Properties * -ErrorAction SilentlyContinue -WarningAction SilentlyContinue |
        Foreach-Object {
                        $userl=$_.Surname+"  "+$_.GivenName+"  "+$_.DisplayName+"  "+$_.SID+"  "+$_.CanonicalName+"  "+$_.EmailAddress+"  "+$_.telephoneNumber
                        "{0} {1}" -f $login, $userl
                       }
}
###############################################################################################################################################################################################################################
Function Stop-ProcessRemote 
{
param (
        [parameter (Mandatory=$true)]
        [string]$ComputerName,
        [parameter (Mandatory=$true)]
        [string]$ProcessName
      )
        $opt = New-CimSessionOption -Protocol DCOM 
        $opt.Timeout = '00:01:00'
        $sess = New-CimSession -ComputerName $ComputerName -SessionOption $opt
        $Process = Get-CimInstance -CimSession $sess -ClassName win32_process -Filter "name = `'$ProcessName`'"
        $reval = (Invoke-CimMethod -InputObject $Process -MethodName Terminate).ReturnValue
                switch ($reval)
                {
                    0       { Write-Host "Process $ProcessName was stopped successfully" -BackgroundColor DarkGreen }
                    default { Write-Host "The process $ProcessName can't be stopped" -BackgroundColor DarkRed }
                }
}
###############################################################################################################################################################################################################################
Function Stop-ProcessUI 
{
 param (
        [parameter (Mandatory=$true)]
        [string]$ComputerName
       )

    $erses = $null
    $opt = New-CimSessionOption -Protocol DCOM 
    $opt.Timeout = '00:01:00'
    $sess = New-CimSession -ComputerName $ComputerName -SessionOption $opt -ErrorVariable erses
    $exit = $null
    if ($erses.Count -ne 0) 
                            {
                                Write-Host 'WMI SESSION WAS NOT ESTABLISHED' -BackgroundColor DarkRed
                                break
                            }
    else                    {
                                while ($null -eq $exit) 
                                {
                                    $reval = $null
                                    $proc = Get-CimInstance -CimSession $sess -ClassName Win32_Process
                                    $proc2 = $proc | Select-Object -Property PSComputerName, ProcessName, CommandLine, CreationDate, ProcessId, WindowsVersion | Out-GridView -Title 'KILL PROCESS' -OutputMode Single
                                    $id = $proc2.ProcessID
                                    $name = $proc2.ProcessName
                                    $Process = Get-CimInstance -CimSession $sess -ClassName Win32_Process | where-Object { $_.ProcessId -eq "$id" }
                                    $reval = (Invoke-CimMethod -InputObject $Process -MethodName Terminate).ReturnValue
                                    Write-Host "Return code is $reval" -BackgroundColor DarkCyan
                                    if     ($reval -eq 0)
                                                            {
                                                                Write-Host "Process $name was stopped successfully `n" -BackgroundColor DarkGreen 
                                                            }
                                    elseif ($null -eq $proc2)
                                                            {
                                                                Write-Host "Commandlet was Exited `n" -BackgroundColor DarkGreen
                                                                $exit = 'exit'
                                                            }
                                    else 
                                                            {
                                                                Write-Host "THE process $name cannot be stopped `n" -BackgroundColor DarkRed 
                                                            }
                                }
                            }
}
###############################################################################################################################################################################################################################
Function Get-SystemUpTime {
param (
[parameter (Mandatory=$true)]
[string]$ComputerName
)
$ping = Test-Connection $ComputerName -count 1 -Quiet
if ($ping) {
$opt         = New-CimSessionOption -Protocol DCOM 
$opt.Timeout = '00:00:10'
$sess        = New-CimSession -ComputerName $ComputerName -SessionOption $opt
$os = Get-CimInstance -CimSession $sess -ClassName Win32_OperatingSystem -OperationTimeoutSec 10
#$boottime = [System.Management.ManagementDateTimeConverter]::ToDateTime($os.LastBootupTime)
$boottime = $os.LastBootupTime
$timedifference = New-TimeSpan -Start $boottime
$days  = $timedifference.Days
$hours = $timedifference.Hours
$min   = $timedifference.Minutes
"$ComputerName system is running for {0} days, {1} hours, {2} minutes." -f $days, $hours, $min
}
else {Write-Host "Computer $ComputerName is Offline" -BackgroundColor DarkRed}
}
###############################################################################################################################################################################################################################
Function Get-SystemTime {
param (
[parameter (Mandatory=$true)]
[string]$ComputerName
)
$ping = Test-Connection $ComputerName -count 1 -Quiet
if ($ping) {
$opt         = New-CimSessionOption -Protocol DCOM 
$opt.Timeout = '00:00:10'
$sess        = New-CimSession -ComputerName $ComputerName -SessionOption $opt

$os = Get-CimInstance -CimSession $sess -ClassName Win32_OperatingSystem -OperationTimeoutSec 10
$Loctime = $os.LocalDateTime
"Date and time on PC $ComputerName are $Loctime"
}
else {Write-Host "Computer $ComputerName is Offline" -BackgroundColor DarkRed}
}
###############################################################################################################################################################################################################################
Function Get-OS {
        param (
                [parameter (Mandatory=$true)]
                [string]$ComputerName
              )

$ping = Test-Connection $ComputerName -count 1 -Quiet
if ($ping) {
$opt         = New-CimSessionOption -Protocol DCOM 
$opt.Timeout = '00:00:10'
$sess        = New-CimSession -ComputerName $ComputerName -SessionOption $opt

$op             = Get-CimInstance -CimSession $sess -ClassName Win32_OperatingSystem -OperationTimeoutSec 10
$psComp         = $op.PSComputerName
$Loctime        = $op.LocalDateTime
$Locale         = $op.Locale
$LastBoot       = $op.LastBootupTime
$OSname         = $op.Caption
$InstallDate    = $op.InstallDate
$MUILanguages   = $op.MUILanguages
$OSArchitecture = $op.OSArchitecture
$RegisteredUser = $op.RegisteredUser
$SerialNumber   = $op.SerialNumber
$OSversion      = $op.Version
$Windir         = $op.WindowsDirectory

$OSoutput = New-Object -TypeName PSObject
Add-Member -InputObject $OSoutput -Type NoteProperty -Name 'ComputerName'     -Value "$psComp"
Add-Member -InputObject $OSoutput -Type NoteProperty -Name 'LocalDateTime'    -Value "$Loctime"
Add-Member -InputObject $OSoutput -Type NoteProperty -Name 'Locale'           -Value "$Locale"
Add-Member -InputObject $OSoutput -Type NoteProperty -Name 'LastBootupTime'   -Value "$LastBoot"
Add-Member -InputObject $OSoutput -Type NoteProperty -Name 'Caption'          -Value "$OSname"
Add-Member -InputObject $OSoutput -Type NoteProperty -Name 'InstallDate'      -Value "$InstallDate"
Add-Member -InputObject $OSoutput -Type NoteProperty -Name 'MUILanguages'     -Value "$MUILanguages"
Add-Member -InputObject $OSoutput -Type NoteProperty -Name 'OSArchitecture'   -Value "$OSArchitecture"
Add-Member -InputObject $OSoutput -Type NoteProperty -Name 'RegisteredUser'   -Value "$RegisteredUser"
Add-Member -InputObject $OSoutput -Type NoteProperty -Name 'SerialNumber'     -Value "$SerialNumber"
Add-Member -InputObject $OSoutput -Type NoteProperty -Name 'Version'          -Value "$OSversion"
Add-Member -InputObject $OSoutput -Type NoteProperty -Name 'WindowsDirectory' -Value "$Windir"
Write-Output $OSoutput
}
else {Write-Host "Computer $ComputerName is Offline" -BackgroundColor DarkRed}
}
###############################################################################################################################################################################################################################
Function Get-Comp {
param (
[parameter (Mandatory=$true)]
[string]$ComputerName
)
$ping = Test-Connection $ComputerName -count 1 -Quiet
if ($ping) {
$opt = New-CimSessionOption -Protocol DCOM 
$opt.Timeout = '00:00:10'
$sess = New-CimSession -ComputerName $ComputerName -SessionOption $opt

$cs       = Get-CimInstance -CimSession $sess -ClassName Win32_ComputerSystem -OperationTimeoutSec 10
$pr       = Get-CimInstance -CimSession $sess -ClassName Win32_Processor -OperationTimeoutSec 10
$ld       = [Math]::Round((Get-CimInstance -CimSession $sess -ClassName win32_LogicalDisk -Filter "DeviceID='C:'" -OperationTimeoutSec 10).FreeSpace/1GB) 
$Net      = Get-CimInstance -CimSession $sess -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -OperationTimeoutSec 10
$sn       = (Get-CimInstance -CimSession $sess -ClassName Win32_Bios -OperationTimeoutSec 10).SerialNumber
$ramreq   =  Get-CimInstance -CimSession $sess -ClassName win32_physicalmemory  -Filter "DeviceLocator!='SYSTEM ROM'" -OperationTimeoutSec 10
$ramreqp   = @($ramreq.Capacity)
$ramp = 0
foreach ($i in $ramreqp)
    { 
        $ramp += $i  
    }
        $rampt = ($ramp/1MB)
$psComp   = $cs.PSComputerName
$model    = $cs.Model
$OSram    = [Math]::Round($cs.TotalPhysicalMemory/1MB)
$userName = $cs.UserName
$prnc     = $pr.NumberOfCores
$prlp     = $pr.NumberOfLogicalProcessors
$prcs     = $pr.MaxClockSpeed
$prpn     = $pr.Name
$mac      = $Net.MACAddress
$ipad     = $Net.IPAddress
$ad       = Get-ADComputer "$ComputerName" -Properties *
$adname   = $ad.CanonicalName
$samname  = $ad.SamAccountName
$lPassset = $ad.PasswordLastSet
$descrip  = $ad.Description
$enable   = $ad.Enabled

$output = New-Object -TypeName PSObject
Add-Member -InputObject $output -Type NoteProperty -Name 'ComputerName'   -Value "$psComp"
Add-Member -InputObject $output -Type NoteProperty -Name 'Model'          -Value "$model"
Add-Member -InputObject $output -Type NoteProperty -Name 'SerialNumber'   -Value "$sn"
Add-Member -InputObject $output -Type NoteProperty -Name 'MAC'            -Value "$mac"
Add-Member -InputObject $output -Type NoteProperty -Name 'IPAddress'      -Value "$ipad"
Add-Member -InputObject $output -Type NoteProperty -Name 'FreeSpaceOnC:\' -Value "$ld"
Add-Member -InputObject $output -Type NoteProperty -Name 'UserName'       -Value "$userName"
Add-Member -InputObject $output -Type NoteProperty -Name 'ProcName'       -Value "$prpn"
Add-Member -InputObject $output -Type NoteProperty -Name 'ProcCores'      -Value "$prnc"
Add-Member -InputObject $output -Type NoteProperty -Name 'ProcLogProcs'   -Value "$prlp"
Add-Member -InputObject $output -Type NoteProperty -Name 'ProcSpeed'      -Value "$prcs"
Add-Member -InputObject $output -Type NoteProperty -Name 'ChipRAM'        -Value "$rampt"
Add-Member -InputObject $output -Type NoteProperty -Name 'OSRAM'          -Value "$OSram"
Add-Member -InputObject $output -Type NoteProperty -Name 'CanonicalName'  -Value "$adname"
Add-Member -InputObject $output -Type NoteProperty -Name 'SamAccountName' -Value "$samname"
Add-Member -InputObject $output -Type NoteProperty -Name 'PwdLastSet'     -Value "$lPassset"
Add-Member -InputObject $output -Type NoteProperty -Name 'ActDirEnable'   -Value "$enable"
Add-Member -InputObject $output -Type NoteProperty -Name 'Description'    -Value "$descrip"

Write-Output $output

}
else {
$output = New-Object -TypeName PSObject
$ad       = Get-ADComputer "$ComputerName" -Properties *
$adname   = $ad.CanonicalName
$samname  = $ad.SamAccountName
$lPassset = $ad.PasswordLastSet
$descrip  = $ad.Description
$enable   = $ad.Enabled

Add-Member -InputObject $output -Type NoteProperty -Name 'ComputerName'    -Value "$ComputerName"
Add-Member -InputObject $output -Type NoteProperty -Name 'Status'          -Value "Offline"
Add-Member -InputObject $output -Type NoteProperty -Name 'CanonicalName'   -Value "$adname"
Add-Member -InputObject $output -Type NoteProperty -Name 'SamAccountName'  -Value "$samname"
Add-Member -InputObject $output -Type NoteProperty -Name 'PasswordLastSet' -Value "$lPassset"
Add-Member -InputObject $output -Type NoteProperty -Name 'Enabled'         -Value "$enable"
Add-Member -InputObject $output -Type NoteProperty -Name 'Description'     -Value "$descrip"

Write-Output $output
}}
###############################################################################################################################################################################################################################
Function icmps {
Test-Connection -ComputerName $args -ErrorAction SilentlyContinue -Count 2
}
###############################################################################################################################################################################################################################
Function shr 
                {
                    Test-Path \\$Args\c$
                }
###############################################################################################################################################################################################################################
Function DNS 
                {
                    [system.net.dns]::GetHostEntry("$args") | Format-List *
                }
###############################################################################################################################################################################################################################
Function Get-GPRes 
{
    param (
    [parameter (Mandatory=$true)]
    [string]$ComputerName,
    [parameter (Mandatory=$true)]
    [string]$LogPath 
    ) 
        $opt = New-CimSessionOption -Protocol DCOM 
        $opt.Timeout = '00:01:00'
        $sess = New-CimSession -ComputerName $ComputerName -SessionOption $opt
        $UserName = ((Get-CimInstance -CimSession $sess -ClassName Win32_ComputerSystem).UserName)
        Get-GPResultantSetOfPolicy -Path $LogPath\PSGPReport_"$ComputerName".html -ReportType Html -Computer $ComputerName -User $UserName
}
###############################################################################################################################################################################################################################
function Test-Port
{
    Param([string]$ComputerName, $port = 5985, $timeout = 1000)
 
    try
    {
        $tcpclient = New-Object -TypeName system.Net.Sockets.TcpClient
        $iar = $tcpclient.BeginConnect($ComputerName,$port,$null,$null)
        $wait = $iar.AsyncWaitHandle.WaitOne($timeout,$false)
        if(!$wait)
        {
            $tcpclient.Close()
            return $false
        }
        else
        {
            # Close the connection and report the error if there is one
            
            $null = $tcpclient.EndConnect($iar)
            $tcpclient.Close()
            return $true
        }
    }
    catch 
    {
        $false 
    }
}
###############################################################################################################################################################################################################################
Function Get-CertRemoteMachine
{
    [CmdletBinding()]
    param (
            [parameter (Mandatory=$true)]
            [string]$ComputerName,
            [parameter (Mandatory=$true, HelpMessage="Store Name values: [AddressBook][AuthRoot][CertificateAuthority][Disallowed][My][Root][TrustedPeople][TrustedPublisher]")]
            [string]$StoreName,
            [parameter (Mandatory=$true, HelpMessage="Store Location values: [CurrentUser][LocalMachine]")]
            [string]$StoreLocation
          )

    $store = New-Object Security.Cryptography.X509Certificates.X509Store("\\$ComputerName\$StoreName", $StoreLocation)
    $store.Open("ReadOnly")
    $store.Certificates | Format-List *
    $store.Close()
}
###############################################################################################################################################################################################################################
Function Remove-CertRemoteMachine
{
    [CmdletBinding()]
    param (
            [parameter (Mandatory=$true)]
            [string]$ComputerName,
            [parameter (Mandatory=$true, HelpMessage="Store Name values: [AddressBook][AuthRoot][CertificateAuthority][Disallowed][My][Root][TrustedPeople][TrustedPublisher]")]
            [string]$StoreName,
            [parameter (Mandatory=$true, HelpMessage="Store Location values: [CurrentUser][LocalMachine]")]
            [string]$StoreLocation,
            [parameter (Mandatory=$true)]
            [string]$Thumbprint
          )

    $store = New-Object Security.Cryptography.X509Certificates.X509Store( "\\$ComputerName\$StoreName", $StoreLocation )
    $store.Open("ReadWrite")
    $cert = $store.Certificates.Find("FindByThumbprint", $Thumbprint, $false)[0]
    $store.Remove($cert)
    $store.Close()
}
###############################################################################################################################################################################################################################
Function Get-ObjectNameBySID
    {
    param (
            [parameter (Mandatory=$true)]
            [string]$SID
          )
        $SIDToName = new-object security.principal.securityidentifier $SID
        $SIDToName.translate([security.principal.ntaccount]) | Select-Object -ExpandProperty Value
    }
###############################################################################################################################################################################################################################
Function Get-LockingProcess 
{
[cmdletbinding()]
Param (
        [Parameter(Position=0,Mandatory=$True,
        HelpMessage="What is the path or filename? You can enter a partial name without wildcards")]
        [Alias("name")]
        [ValidateNotNullorEmpty()]
        [string]$Path
      )
 
    #define the path to Handle.exe
    $Handle = "c:\Windows\PS\SysinternalsSuite\handle.exe"
 
    [regex]$matchPattern = "(?<Name>\w+\.\w+)\s+pid:\s+(?<PID>\d+)\s+type:\s+(?<Type>\w+)\s+(?<User>\S+)\s+\w+:\s+(?<Path>.*)"
 
    $data = &$handle -u $path 
    $MyMatches = $matchPattern.Matches( $data )
 
    if ($MyMatches.value) 
                            {
                              $MyMatches | ForEach-Object {
                              [pscustomobject]@{ 
                              FullName = $_.groups["Name"].value
                              Name = $_.groups["Name"].value.split(".")[0]
                              ID = $_.groups["PID"].value
                              Type = $_.groups["Type"].value
                              Path = $_.groups["Path"].value
	                          User = $_.groups["User"].value
                              toString = "pid: $($_.groups["PID"].value), user: $($_.groups["User"].value), image: $($_.groups["Name"].value)"
                              } #hashtable
                              } #foreach
                            } #if data
    else {
            Write-Warning "No matching handles found"
         }
}
###############################################################################################################################################################################################################################
Function Get-AllHardDisks 
{
        param (
                [parameter (Mandatory=$true)]
                [string]$ComputerName
              )

    $opt = New-CimSessionOption -Protocol DCOM
    $sess = New-CimSession -ComputerName $ComputerName -SessionOption $opt
    $dskdr = Get-CimInstance -CimSession $sess -ClassName win32_diskdrive
    $sz = @($dskdr.Size)
    $cds = (@($dskdr.DeviceID)).Count
    $model = @($dskdr.Model) -join " | "
    $interf = @($dskdr.InterfaceType) -join " | "
    $part = @($dskdr.Partitions) -join " | "
    $detPart = @()
    foreach ($dsk in $sz)
    {
        $detPart += [Math]::Round($dsk/1GB)
    }
    $tdetPart = $detPart -join " | "

    $tsz = 0
    foreach ($dsk in $sz)
    {
        $tsz += $dsk
    }
    $totsz = [Math]::Round($tsz/1GB)

    Write-Host ("{0}     {1}     {2}     {3}     {4}     {5}" -f $cds, $totsz, $model, $tdetPart, $interf, $part) -BackgroundColor DarkCyan
    ""
}
###############################################################################################################################################################################################################################
Function Get-LocalProfiles 
{
 param (
        [parameter (Mandatory=$true)]
        [string]$ComputerName
       )

    $opt = New-CimSessionOption -Protocol DCOM 
    $opt.Timeout = '00:01:00'
    $sess = New-CimSession -ComputerName $ComputerName -SessionOption $opt
    Get-CimInstance -CimSession $sess -ClassName Win32_UserProfile | Select-Object LOADED, LOCALPATH, SID, LASTUSETIME, Special, Status, RoamingConfigured | Format-Table -AutoSize
}
###############################################################################################################################################################################################################################
## ?????????? ??????? ????????? ????? ???????? Windows
## ?????? ???????????? PowerShell ?????? 2.0 (????????? ??? ???? ?????? Windows)
Function Get-WindowsProduct {
## ??????? ?????????? ???? ????????????? Windows ? ????? ?????? ? ????, ???? ??????? ???? ?? ????????????? ??????. ????? ??? ?????? ????????????? ????????? ? ?????
param ($Targets = [System.Net.Dns]::GetHostName())
function PIDDecoderFromRegistry($digitalProductId) {
New-Variable -Name base24 -Value 'BCDFGHJKMPQRTVWXY2346789' ## -Option Const ## <24> ??????? ?????????????? ? ?????? ???????? Windows ? Office
New-Variable -Name decodeStringLength -Value 24 ## -Option Const ## �??????� ????? ?????????????? ????? ????????
New-Variable -Name decodeLength -Value 14 ## -Option Const ## ????? ?????????????? ????? ???????? ? ?????? (??????? ???????? ? ??????????)
New-Variable -Name decodedKey -Value ([System.String]::Empty) ## ?????? ?????????? ?????????????? ???? ????????
## ????????, ???????? ?? ???? ???????? �N� (????? ???????? ??? Windows 8 ? Office 15)
$containsN = ($digitalProductId[$decodeLength] / 8) -bAnd 1 ## ($digitalProductId[$decodeLength] -shr 3) -bAnd 1 ## PS 4.0
$digitalProductId[$decodeLength] = [System.Byte]($digitalProductId[$decodeLength] -bAnd [System.Convert]::ToByte('F7', 16)) ## 247
## ?????????? ??????? ???????????
for ($i = $decodeStringLength; $i -ge 0; $i--)
{
$digitMapIndex = 0
for ($j = $decodeLength; $j -ge 0; $j--)
{
$digitMapIndex = $digitMapIndex * 256 -bXor $digitalProductId[$j] ## $digitMapIndex -shl 8 -bXor $digitalProductId[$j] ## PS 4.0
$digitalProductId[$j] = [System.Math]::Truncate($digitMapIndex / $base24.Length)
$digitMapIndex = $digitMapIndex % $base24.Length
}
$decodedKey = $decodedKey.Insert(0, $base24[$digitMapIndex])
}
## ???????? ??????? ??????? ? ????? ? ????????? �N� ? ?????? ???????
if ([System.Boolean]$containsN)
{
$firstLetterIndex = 0
for ($index = 0; $index -lt $decodeStringLength; $index++)
{
if ($decodedKey[0] -ne $base24[$index]) {continue}
$firstLetterIndex = $index
break
}
$keyWithN = $decodedKey
$keyWithN = $keyWithN.Remove(0, 1)
$keyWithN = $keyWithN.Substring(0, $firstLetterIndex) + 'N' + $keyWithN.Remove(0, $firstLetterIndex)
$decodedKey = $keyWithN;
}
$returnValue = $decodedKey
## ??????? ???? ????? ?????? ???? ????????
for ($t = 20; $t -ge 5; $t -= 5)
{
$returnValue = $returnValue.Insert($t, '-')
}
return $returnValue
}
## Main
New-Variable -Name hklm -Value 2147483650 ## -Option Const
New-Variable -Name regPath -Value 'Software\Microsoft\Windows NT\CurrentVersion' ## -Option Const
New-Variable -Name regValue -Value 'DigitalProductId' ## -Option Const
Foreach ($target in $Targets) {
$opt = New-CimSessionOption -Protocol DCOM 
$opt.Timeout = '00:01:00'
$sess = New-CimSession -ComputerName $target -SessionOption $opt
$win32os = $null
$wmi = [WMIClass]"\\$target\root\default:stdRegProv"
$binArray = $wmi.GetBinaryValue($hklm,$regPath,$regValue).uValue[52..66]
$win32os = Get-CimInstance -CimSession $sess -ClassName Win32_OperatingSystem
$product = New-Object -TypeName System.Object
## ???????????
$product | Add-Member -MemberType 'NoteProperty' -Name 'Computer' -Value $target
$product | Add-Member -MemberType 'NoteProperty' -Name 'Caption' -Value $win32os.Caption
$product | Add-Member -MemberType 'NoteProperty' -Name 'CSDVersion' -Value $win32os.CSDVersion
$product | Add-Member -MemberType 'NoteProperty' -Name 'OSArch' -Value $win32os.OSArchitecture
$product | Add-Member -MemberType 'NoteProperty' -Name 'BuildNumber' -Value $win32os.BuildNumber
$product | Add-Member -MemberType 'NoteProperty' -Name 'RegisteredTo' -Value $win32os.RegisteredUser
$product | Add-Member -MemberType 'NoteProperty' -Name 'ProductID' -Value $win32os.SerialNumber
$product | Add-Member -MemberType 'NoteProperty' -Name 'ProductKey' -Value (PIDDecoderFromRegistry($binArray))
Write-Output $product
}
} ## End Get-WindowsProduct
###############################################################################################################################################################################################################################
Function Get-MainADInfo 
{
    param (
        [parameter (Mandatory=$true)]
        [string]$ComputerName
       )
    $adInfo = Get-ADComputer $ComputerName -Properties * 

$MainADInfo = New-Object -TypeName PSObject
Add-Member -InputObject $MainADInfo -Type NoteProperty -Name 'Enabled'                     -Value "$($adInfo.enabled)"
Add-Member -InputObject $MainADInfo -Type NoteProperty -Name 'Passwordlastset'             -Value "$($adInfo.passwordlastset)"
Add-Member -InputObject $MainADInfo -Type NoteProperty -Name 'LastLogonTimestamp'          -Value "$([datetime]::FromFileTime($adInfo.lastLogonTimestamp))"
Add-Member -InputObject $MainADInfo -Type NoteProperty -Name 'canonicalname'               -Value "$($adInfo.canonicalname)"
Add-Member -InputObject $MainADInfo -Type NoteProperty -Name 'DistinguishedName'           -Value "$($adInfo.DistinguishedName)"
Add-Member -InputObject $MainADInfo -Type NoteProperty -Name 'Created'                     -Value "$($adInfo.Created)"
Add-Member -InputObject $MainADInfo -Type NoteProperty -Name 'IPv4Address'                 -Value "$($adInfo.IPv4Address)"
Add-Member -InputObject $MainADInfo -Type NoteProperty -Name 'LastLogonDate'               -Value "$($adInfo.LastLogonDate)"
Add-Member -InputObject $MainADInfo -Type NoteProperty -Name 'ms-Mcs-AdmPwd'               -Value "$($adInfo.'ms-Mcs-AdmPwd')"
Add-Member -InputObject $MainADInfo -Type NoteProperty -Name 'ms-Mcs-AdmPwdExpirationTime' -Value "$([datetime]::FromFileTime($adInfo.'ms-Mcs-AdmPwdExpirationTime'))"
Add-Member -InputObject $MainADInfo -Type NoteProperty -Name 'OperatingSystem'             -Value "$($adInfo.OperatingSystem)"
Add-Member -InputObject $MainADInfo -Type NoteProperty -Name 'OperatingSystemVersion'      -Value "$($adInfo.OperatingSystemVersion)"
Add-Member -InputObject $MainADInfo -Type NoteProperty -Name 'whenCreated'                 -Value "$($adInfo.whenCreated)"
Add-Member -InputObject $MainADInfo -Type NoteProperty -Name 'whenChanged'                 -Value "$($adInfo.whenChanged)"
Add-Member -InputObject $MainADInfo -Type NoteProperty -Name 'Description'                 -Value "$($adInfo.Description)"

Write-Output $MainADInfo
}
###############################################################################################################################################################################################################################
#Function Prompt
#{
#    $testArchPOSH = [Environment]::Is64BitProcess
#    switch ($testArchPOSH)
#    {
#        $true   {$ArchPOSH = 'x64'}
#        $false  {$ArchPOSH = 'x86'}
#        Default {$ArchPOSH = 'Unknown architecture'}
#    }
#    $title = "$ArchPOSH [$(Get-Location)]"
#    #Write-Host $(Get-Date -Format dd.MM.yy"`n"HH:mm:ss) #-BackgroundColor DarkGreen
#    $loc = Get-Location
#    $ss = $loc.Path.LastIndexOf("\")
#    $folder = $loc.Path.Substring($ss + 1)
#    $version = $PSVersionTable.PSVersion.Major
#    "$version.v $folder >> "
#    $host.UI.RawUI.WindowTitle = $title
#}
###############################################################################################################################################################################################################################
Function Get-Dump{
param (
        [parameter (Mandatory=$true)]
        [string]$ComputerName,
        [parameter (Mandatory=$true)]
        [string]$Destination
      )
    $source = "\\$ComputerName\c$\windows"
    $dmp    = "\\$ComputerName\c$\windows\MEMORY.DMP"
    $png    = Test-Connection $ComputerName -Count 2 -Quiet
    $src    = Test-Path $source   
    $mmr    = Test-Path $dmp
    if ($png)
        {
            if ($src)
                {
                    if ($mmr)
                    {
                        if (Test-Path $Destination\MEMORY_$ComputerName.DMP)
                        {
                            $rnd = Get-Date -Format "yyMMdd_HHmmss"
                            Rename-Item -Path $Destination\"MEMORY_$ComputerName.DMP" -NewName "MEMORY_$ComputerName`_$rnd.DMP"
                            Write-Host "`nMemory dump on $Destination was renamed to MEMORY_$ComputerName`_$rnd.DMP" -BackgroundColor DarkGreen
                        }
                        if (Test-Path $source\MEMORY_$ComputerName.DMP)
                        {
                            Remove-Item -Path $source\MEMORY_$ComputerName.DMP -Force
                            Write-Host "`nRenamed memory dump on $source was removed" -BackgroundColor DarkGreen
                        }
                        Rename-Item -Path $source\MEMORY.DMP -NewName "MEMORY_$ComputerName.DMP"
                        robocopy $source $Destination "MEMORY_$ComputerName.DMP" /Z /COPY:DAT /MT:30 /R:100000 /W:20  
                        Rename-Item -Path $source\MEMORY_$ComputerName.DMP -NewName 'MEMORY.DMP'
                    }
                    else
                        {
                            Write-Host "$dmp does not exist" -BackgroundColor DarkRed
                        }
                }
            else
                {
                    Write-Host "$source is not avaliable" -BackgroundColor DarkRed
                }
        }
    else
        {
            Write-Host "$ComputerName is offline" -BackgroundColor DarkRed
        }
}
###############################################################################################################################################################################################################################
Function Start-Robocopy{
param (
        [parameter (Mandatory=$true)]
        [string]$Source,
        [parameter (Mandatory=$true)]
        [string]$Destination,
        [parameter (Mandatory=$true)]
        [string]$File
      )

    $src  = Test-Path $Source
    $srcf = Test-Path $Source\$File
    $dst  = Test-Path $Destination
    if ($src)
        {
            if($srcf)
            {
                if ($dst)
                    {
                        if (Test-Path $Destination\$File)
                        {
                            $rnd = Get-Date -Format "yyMMdd_HHmmss"
                            Rename-Item -Path $Destination\$File -NewName $File`_$rnd -Force
                            Write-Host "`nFile on $Destination was renamed to $File`_$rnd" -BackgroundColor DarkGreen
                        }
                        robocopy $Source $Destination $File /Z /COPY:DAT /MT:30 /R:100000 /W:20  
                    }
                else
                    {
                        Write-Host "There is no $Destination" -BackgroundColor DarkRed
                    }
            }
            else
            {
                Write-Host "$Source\$File does not exist" -BackgroundColor DarkRed
            }
        }
    else
        {
            Write-Host "$source is not avaliable" -BackgroundColor DarkRed
        }
}
###############################################################################################################################################################################################################################
function Get-DumpAnalysis
{
<#
.SYNOPSIS
Automates minidump analysis.

.DESCRIPTION
The CDB $< command allows you read in a text file and each line be executed
in the CDB command line. When you start CDB with the -c command line switch
you can tell it to execute specific commands. Thus if you use the following 
-c option, you can script CDB.

  cdb.exe -c "$$<Commands.txt"

This script wraps up the CDB -c trick to let you pipe in a bunch of files 
and have the same commands run on all individual files. All output is TEE'd
to the screen and to a file. 

The log file written will be named <minidump name>-<debugscriptname>.log

.PARAMETER Files
The minidump files to process.

.PARAMETER DebuggingScript
The script file to pass to CDB. You specify the CDB commands in this file one
line at a time. For comments, CDB supports using the "*" character at the start
of the line.

.PARAMETER CdbProgramPath
By default this script assumes that CDB is the PATH environment variable. If you 
would like to specify the particular CDB to run, put the full path and CDB.EXE
into this parameter.

.EXAMPLE
Get-DumpAnalysis -Files .\MyMiniDump.dmp -DebuggingScript .\BasicAnalysis.txt

This will run the commands in BasicAnalysis.txt on MyMiniDump.dmp and the output will be
writting to MyMiniDump.dmp-BasicAnalysis.txt.log

.EXAMPLE
Get-ChildItem *.dmp | Get-DumpAnalsys -DebuggingScript .\MoreStuff.txt

For all mini dump files will be piped to Get-DumpAnalysis and have the debug script 
MoreStuff.txt run on each one.

.NOTES
Here is an example of a debugging script. Note that asterisks are treated as comments
by CDB but are output to the log. It's a good idea to use comments so you can identify
where different commands run so you can use a regular expression to pull them out.

* Do the basic analysis
!analyze -v
* Get all the loaded modules 
lmv

.LINK
http://www.wintellect.com/devcenter/author/jrobbins
https://github.com/Wintellect/WintellectPowerShell

 #>

    [CmdletBinding(SupportsShouldProcess=$true)]
    param
    (
        [Parameter(ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Mandatory=$true,
                   HelpMessage="Please enter the minidump file to process")]
        [Alias('FullName')]
        [string]$Files,
    
        [Parameter(Mandatory=$true,
                   HelpMessage="Please enter WinDBG script file to use")]
        [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
        [string]$DebuggingScript,

        [AllowEmptyString()]
        [string]$CdbProgramPath="",

        [AllowEmptyString()]
        [string]$SymbolsPath=""
    )
 
    begin
    {
        # If the path to the version of cdb is null, use the first one 
        # found in the path.
        if ($CdbProgramPath.Length -eq 0)
        {
            $CdbProgramPath = (Get-Command -Name "cdb.exe" -ErrorAction Stop).Source
        }
        Test-Path -Path $CdbProgramPath -ErrorAction Stop | Out-Null
        Write-Verbose -Message "Using cdb from $CdbProgramPath"

        # If the path to the debug symbols is null, use the static 'd:\WinDDK\symbols\' system path.
        if ($SymbolsPath.Length -eq 0)
        {
            $SymbolsPath = 'd:\WinDDK\symbols\'
        }
        Test-Path -Path $SymbolsPath -ErrorAction Stop | Out-Null
        Write-Verbose -Message "Using debug symbols from $SymbolsPath"


    }
    process
    {
        foreach ($file in $Files)
        {
            $scriptName = [System.IO.Path]::GetFileName($DebuggingScript)
            $fullScriptPath = (Resolve-Path -Path $DebuggingScript).Path

            $file = (Resolve-Path -Path $file).Path
            $logFile = $file + "-" + $scriptName + ".log"

            Write-Verbose -Message "Logging to file $logFile"

            if ($PSCmdlet.ShouldProcess("$CdbProgramPath -z $file -c `"`$$<$fullScriptPath;q`" -y $SymbolsPath", "Executing"))
            {
                &$CdbProgramPath -z $file -c "`$`$<$fullScriptPath;Q" -y $SymbolsPath | Tee-Object -FilePath $logFile
            }
        }
    }
}
###############################################################################################################################################################################################################################
Function Test-DHCPReservation
{
    [CmdletBinding()]
    param (
            [parameter (Mandatory=$true, HelpMessage="NetBios Name without 'domain name' which should be found")]
            [ValidateNotNullOrEmpty()]
            [string]$ComputerName,
            [parameter (Mandatory=$true, HelpMessage="For instance, server name - server name for HO")]
            [ValidateNotNullOrEmpty()]
            [string]$ServerDHCPName,
            [parameter (Mandatory=$true, HelpMessage="It should be IP address formal like '10.10.10.0' ")]
            [ValidateNotNullOrEmpty()]
            [string]$ScopeIDName
          )

    Get-DhcpServerv4Reservation -ComputerName $ServerDHCPName -ScopeId $ScopeIDName | Where-Object {$_.name -eq "$ComputerName"} | Format-List -Property Name, IPAddress, ClientId, ScopeId, AddressState, Type, Description
}
###############################################################################################################################################################################################################################
Function Get-InstalledUpdatesSession 
{

[CmdletBinding()]
    param (
            [parameter (Mandatory=$true, HelpMessage="NetBios Name without 'domain name' which should be found")]
            [ValidateNotNullOrEmpty()]
            [string]$ComputerName,
            [parameter (Mandatory=$true, HelpMessage="For instance: 'KB3085560', 'KB3085572', ...")]
            [ValidateNotNullOrEmpty()]
            [array]$KBIDs
          )

    $Session  = [activator]::CreateInstance([type]::GetTypeFromProgID("Microsoft.Update.Session","$ComputerName"))
    $Searcher = $Session.CreateUpdateSearcher()
    $historyCount = $Searcher.GetTotalHistoryCount()

    $status = @{
        Name="Operation"
        Expression= {
            switch($_.operation)
            {
                1 {"Installation"}
                2 {"Uninstallation"}
                3 {"Other"}
            }
        }
    }
    $totalUpdates = $Searcher.QueryHistory(0, $historyCount) | Select-Object Title, Date, $status 
    $KBs = @($KBIDs)
    foreach ($kb in $KBs) {
                                $totalUpdates |  Where-Object  {$_.Title -like "*$kb*"}
                          }
}
###############################################################################################################################################################################################################################
function Test-DayProperties {

<# MIT License

    Copyright (c) 2017 Kirill Nikolaev

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
#>

<#
.SYNOPSIS
    Tests the given date against different conditions.

.DESCRIPTION
    The function helps you to detect if today is the third Tuesday in a month, if the date belongs to some quarter, if today is the last day of a month etc.

.PARAMETER Date
    The date object which you are testing. By default, the current date/time.

.PARAMETER DayOfWeek
    Use to test if the day is the defined day in a week (Mon, Tue, Wed etc).

.PARAMETER NumberInMonth
    Use to detect if the day is the specified number of the day type defined in the DayOfWeek parameter.

.PARAMETER EndOfMonth
    Use to detect if the given day is the last day of the month.

.PARAMETER Quarter
    Use to detect if the given day is belongs to the specified quarter.

.PARAMETER QuarterType
    Use to detect if the given day is the start or the end of the specified quarter.

.PARAMETER Last
    Use to detect if the given day is the last day of some kind in the given month. If the DayOfWeek parameter is omitted, the kind of day is extracted from the Date parameter, otherwise � DayOfWeek is used.

.EXAMPLE
    Test-DayProperties -DayOfWeek 2 -NumberInMonth 2
    Tests if the current day is the second Tuesday in this month.

.EXAMPLE
    Test-DayProperties -Date $Date -DayOfWeek 7 -Last
    Tests if the date in the $Date object is the last Sunday in the month.

.EXAMPLE
    Test-DayProperties -Last
    Tests if today is the last day of its kind in the month.

.EXAMPLE
    Test-DayProperties -EndOfMonth
    Tests if today is the last day of the month.

.EXAMPLE
    Test-DayProperties -Date $Date -Quarter 3 -QuarterType End
    Tests if the date in the $Date object is the end (the last day) of the 3rd quarter.

.EXAMPLE
    Test-DayProperties -QuarterType Start
    Tests if today is the beginning of a quarter.

.EXAMPLE
    Test-DayProperties $Date -Quarter 1
    Tests if the date in the $Date object belonngs to the 1st quarter.

.INPUTS
    [DateTime]

.OUTPUTS
    [boolean]

.NOTES
   Author: Kirill Nikolaev
   Twitter: @exchange12rocks

.LINK
    https://exchange12rocks.org/2017/05/29/function-to-test-a-date-against-different-conditions

.LINK
    https://github.com/exchange12rocks/PS/tree/master/Test-DayProperties

#>

#Requires -Version 3.0

    [CmdletBinding(
        DefaultParametersetName='Default'
    )]
    [OutputType([boolean])]
    Param (
        [Parameter(ParameterSetName='Default', Position = 0)]
        [Parameter(ParameterSetName='Quarter', Position = 0)]
        [Parameter(ParameterSetName='QuarterType', Position = 0)]
        [Parameter(ParameterSetName='EndOfMonth', Position = 0)]
        [Parameter(ParameterSetName='Last', Position = 0)]
        [ValidateNotNullorEmpty()]
        [DateTime]$Date = (Get-Date),

        [Parameter(ParameterSetName='Default', Mandatory)]
        [Parameter(ParameterSetName='Last')]
        [ValidateRange(1,7)]
        [int]$DayOfWeek,

        [Parameter(ParameterSetName='Default', Mandatory)]
        [ValidateRange(1,5)] # It's impossible to have more that 5 weeks in a month (on Earth)
        [int]$NumberInMonth,

        [Parameter(ParameterSetName='EndOfMonth')]
        [switch]$EndOfMonth,

        [Parameter(ParameterSetName='Quarter', Mandatory)]
        [Parameter(ParameterSetName='QuarterType')]
        [ValidateRange(1,4)]
        [int]$Quarter,

        [Parameter(ParameterSetName='QuarterType', Mandatory)]
        [ValidateSet('Start','End')]
        [string]$QuarterType,

        [Parameter(ParameterSetName='Last', Mandatory)]
        [switch]$Last

    )

    function GetLastDateOfCurrentMonth {

        Param (
            [ValidateNotNullorEmpty()]
            [DateTime]$Date = (Get-Date)
        )

        $result = $false

        if ($Date.Month -in @(1, 3, 5, 7, 8, 10, 12)) {
            $result = New-Object -TypeName DateTime -ArgumentList @($Date.Year, $Date.Month, 31)
        }
        elseif ($Date.Month -in @(4, 6, 9, 11)) {
            $result = New-Object -TypeName DateTime -ArgumentList @($Date.Year, $Date.Month, 30)
        }
        else { #February
            try {
                $result = New-Object -TypeName DateTime -ArgumentList @($Date.Year, $Date.Month, 29)
            }
            catch {
                if ($Error[0].Exception.InnerException.HResult -eq -2146233086) {
                    $result = New-Object -TypeName DateTime -ArgumentList @($Date.Year, $Date.Month, 28)
                }
            }
        }

        return $result
    }

    function GetDotNETDayOfWeek {
        Param (
            [ValidateRange(1,7)]
            [int]$DayOfWeek
        )

        if ($DayOfWeek -eq 7) {
            return 0
        }
        else {
            return $DayOfWeek
        }
    }

    $result = $false
       
    switch ($PSCmdlet.ParameterSetName) {
        'QuarterType' {
            if ($QuarterType -eq 'Start') {
                if ($Date.Day -eq 1 -and $Date.Month -in (1,4,7,10)) {
                    $result = $true
                    if ($Quarter) {
                        if ($Date.Month -ne (3*$Quarter-2)) {
                            $result = $false
                        }
                    }
                }
            }
            elseif ($QuarterType -eq 'End') {
                if (($Date.Month -in (3,6,9,12)) -and $Date.Day -eq ((GetLastDateOfCurrentMonth -Date $Date).Day)) {
                    $result = $true
                }
            }
        }
        'Quarter' {
            if ($Date.Month -in ((3*$Quarter-2)..(3*$Quarter))) {
                $result = $true
            }
        }
        'EndOfMonth' {
            if ($Date -eq (GetLastDateOfCurrentMonth -Date $Date)) {
                 $result = $true
            }
        }
        'Last' {
            $LastDateOfCurrentMonth = GetLastDateOfCurrentMonth -Date $Date
            $StartOfLast7Days = $LastDateOfCurrentMonth.AddDays(-6)
            if (!$DayOfWeek) {
                if ($Date -ge $StartOfLast7Days -and $Date -le $LastDateOfCurrentMonth) {
                    $result = $true
                }
            }
            elseif ($Date.DayOfWeek.value__ -eq (GetDotNETDayOfWeek -DayOfWeek $DayOfWeek) -and $Date -ge $StartOfLast7Days -and $Date -le $LastDateOfCurrentMonth) {
                $result = $true
            }
        }
        'Default' {
            $DaysToSubstract = (7*($NumberInMonth-1))
            if ((New-TimeSpan -Days $DaysToSubstract).Ticks -le $Date.Ticks) {
                if ($Date.DayOfWeek.value__ -eq (GetDotNETDayOfWeek -DayOfWeek $DayOfWeek) -and $Date.AddDays(-$DaysToSubstract).Month -eq $Date.Month -and $Date.Day -le (7*$NumberInMonth)) {
                    $result = $true
                }
            }
        }
        Default {
            $result = $false
        }
    }
    return $result
}
###############################################################################################################################################################################################################################
Function Set-Signature
{
[cmdletbinding()]
Param (
        [Parameter(Mandatory=$True)]       
        [ValidateNotNullorEmpty()]
        [string]$Path
      )
$cert = Get-ChildItem cert:\CurrentUser\My -CodeSigningCert | Where-Object {$_.Thumbprint -eq "561A9233A561DA0403E994AD57EAF0FFDBA04543"}
Set-AuthenticodeSignature $Path $cert -HashAlgorithm sha256 -TimestampServer "http://timestamp.verisign.com/scripts/timstamp.dll"
}
###############################################################################################################################################################################################################################
Function New-Password
{
[CmdletBinding()]
    param (
            [parameter (Mandatory=$false, HelpMessage='abcdefghkmnrstuvwxyzABCDEFGHKLMNPRSTUVWXYZ23456789$%&*#')]
            [string]$CharSet = 'abcdefghkmnrstuvwxyzABCDEFGHKLMNPRSTUVWXYZ23456789$%&*#',
            [parameter (Mandatory=$false)]
            [int]$PasswordLength = 8
          )

$newPassword = -join ($CharSet.ToCharArray() | Get-Random -Count $PasswordLength)
Write-Host "New Password : $newPassword" -ForegroundColor Cyan
""
}
###############################################################################################################################################################################################################################
Function New-ADComputerAccount
{
[CmdletBinding()]
Param (
        [Parameter(Mandatory=$True)]       
        [ValidateNotNullorEmpty()]
        [string]$ComputerName,
        [Parameter(Mandatory=$True)]       
        [ValidateNotNullorEmpty()]
        [string]$Path,
        [Parameter(Mandatory=$True)]       
        [ValidateNotNullorEmpty()]
        [string]$DotGroup,
        [Parameter(Mandatory=$False)]       
        [ValidateNotNullorEmpty()]
        [string]$Description,
        [Parameter(Mandatory=$False)]       
        [ValidateNotNullorEmpty()]
        [string]$OperatingSystem
      )
$ErrorActionPreference = "SilentlyContinue"
$exception             = 0
try
    {
        New-ADComputer -Name $ComputerName -Path $Path -Description $Description -Enabled $True -OperatingSystem $OperatingSystem
        Write-Host "A new computer object $ComputerName has been created successfully" -BackgroundColor DarkGreen
    }
catch 
    {
        Write-Host "An error was occured." -BackgroundColor DarkRed
        Write-Host  $PSItem.Exception.Message -BackgroundColor DarkRed
        Write-Host  "Detailed information:" -BackgroundColor DarkRed
        $PSItem.InvocationInfo | Select-Object MyCommand, ScriptLineNumber, OffsetInLine, Line, InvocationName | Format-Table -AutoSize -Wrap
        $exception = $PSItem.Exception.Message.Length
    }    
if($exception -eq 0)
    {
        do
            {
                Start-Sleep 1
                $gadc            = $null
                $ComputerNameObj = Get-ADComputer $ComputerName -ErrorVariable gadc
                Write-Host "Please, wait..." -BackgroundColor DarkMagenta
            }
        until ($gadc.count -eq 0)
    
            Try
            {
                Set-ADComputer -Identity $ComputerName -ServicePrincipalNames @{Add="HOST/$ComputerName"}
                $DotGroupObj = Get-ADGroup -Identity $DotGroup
                Add-ADGroupMember -Identity $DotGroupObj -Members $ComputerNameObj
                Write-Host "Attributes of the new computer object $ComputerName have been added successfully." -BackgroundColor DarkGreen
            }
            catch
            {
                Write-Host "An error was occured while setting up attributes and a group." -BackgroundColor DarkRed
                Write-Host  $PSItem.Exception.Message -BackgroundColor DarkRed
                Write-Host  "Detailed information:" -BackgroundColor DarkRed
                $PSItem.InvocationInfo | Select-Object MyCommand, ScriptLineNumber, OffsetInLine, Line, InvocationName | Format-Table -AutoSize -Wrap
                try
                    {
                       Remove-ADComputer -Identity $ComputerName -Confirm:$false
                       Write-Host "A new computer object $ComputerName has been deleted successfully, please, check the errors and rerun the script." -BackgroundColor DarkGreen
                    }
                catch 
                    {
                        Write-Host "An error was occured while deleting the computer object. Exiting the script." -BackgroundColor DarkRed
                        Write-Host  $PSItem.Exception.Message -BackgroundColor DarkRed
                        Write-Host  "Detailed information:" -BackgroundColor DarkRed
                        $PSItem.InvocationInfo | Select-Object MyCommand, ScriptLineNumber, OffsetInLine, Line, InvocationName | Format-Table -AutoSize -Wrap
                    }
            }
    }
else
    {
        Write-Host "Exiting the script." -BackgroundColor DarkRed
    }

Write-Host "The script has been executed." -BackgroundColor DarkMagenta

$ErrorActionPreference = "Continue"
}
###############################################################################################################################################################################################################################

