# ============================================================
# WorkBuddy daily check-in - Event Trigger + Multi-time setup
# Run as ADMINISTRATOR on YOUR OWN PC (not inside the sandbox)
#
# Triggers:
#   1) On network connect (EventID 10000) -> instant claim when you get online
#   2) Daily 09:00 / 12:00 / 15:00 / 18:00 / 21:00 -> multi-time fallback
#
# The check-in script is idempotent (skips if already claimed),
# so firing multiple times per day is safe.
#
# HOW IT WORKS (single, definitive approach):
#   Build the COMPLETE task as an XML string and register it with
#   Register-ScheduledTask -Xml. Passing the XML as a string (not a
#   file) avoids BOTH problems we hit before:
#     - COM: the Settings object is only the base ITaskSettings
#       interface, so MultipleInstancesPolicy/RestartOnFailure are
#       simply not settable via COM in PowerShell 5.1.
#     - Encoding: writing the XML to a file triggered UTF-8/UTF-16
#       schema errors in schtasks. A string has no file encoding.
#   A schtasks fallback (UTF-16 LE BOM temp file) is kept only as a
#   last resort safety net.
# ============================================================

$ErrorActionPreference = "Stop"

$dir  = $PSScriptRoot
$bat  = "$dir\run_checkin.bat"
$name = "WorkBuddy Daily Check-in"
$times = @("09:00:00", "12:00:00", "15:00:00", "18:00:00", "21:00:00")
$today = (Get-Date).ToString("yyyy-MM-dd")

if (-not (Test-Path $bat)) {
    Write-Error "Cannot find entry script: $bat"
    exit 1
}

$userName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

# Event subscription: network just connected (NetworkProfile Operational, EventID 10000).
# Stored as raw XPath; assigned via InnerText later so < > are auto-escaped.
$eventQuery = "<QueryList><Query Id='0' Path='Microsoft-Windows-NetworkProfile/Operational'><Select Path='Microsoft-Windows-NetworkProfile/Operational'>*[System[Provider[@Name='Microsoft-Windows-NetworkProfile'] and EventID=10000]]</Select></Query></QueryList>"

# Build the 5 daily calendar triggers.
$dailyTriggers = ($times | ForEach-Object {
    "    <CalendarTrigger>`n      <StartBoundary>$($today)T$_</StartBoundary>`n      <Enabled>true</Enabled>`n      <ScheduleByDay>`n        <DaysInterval>1</DaysInterval>`n      </ScheduleByDay>`n    </CalendarTrigger>"
}) -join "`n"

# Assemble the full task XML. The event subscription is a placeholder here;
# it is filled in via InnerText below to guarantee correct escaping.
$xml = [xml] @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>$($today)T00:00:00</Date>
    <Author>$userName</Author>
    <Description>WorkBuddy daily check-in: claim on network connect + 5 daily fallbacks</Description>
  </RegistrationInfo>
  <Triggers>
    <EventTrigger>
      <Enabled>true</Enabled>
      <Subscription>__EVENT_SUBSCRIPTION__</Subscription>
    </EventTrigger>
$dailyTriggers
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>$userName</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT10M</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>3</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>$bat</Command>
    </Exec>
  </Actions>
</Task>
"@

# Fill the event subscription via InnerText -> PowerShell auto-escapes < > &.
$xml.Task.Triggers.EventTrigger.Subscription = $eventQuery

$xmlString = $xml.OuterXml

# Debug mode: only emit the XML, do not register. Useful for verifying well-formedness.
if ($env:WB_DEBUG) {
    $out = Join-Path $dir "task_debug.xml"
    [System.IO.File]::WriteAllText($out, $xmlString, [System.Text.Encoding]::Unicode)
    Write-Host "DEBUG: wrote $out"
    exit 0
}

# Validate the XML is well-formed before handing it to the scheduler.
try {
    $check = New-Object System.Xml.XmlDocument
    $check.LoadXml($xmlString)
}
catch {
    Write-Error "Generated XML is not well-formed: $_"
    exit 1
}

$ok = $false

# Primary: Register-ScheduledTask -Xml (string, no file -> no encoding issues).
try {
    Register-ScheduledTask -TaskName $name -Xml $xmlString -Force -ErrorAction Stop
    Write-Host "Primary method (Register-ScheduledTask -Xml) succeeded." -ForegroundColor Green
    $ok = $true
}
catch {
    Write-Warning "Register-ScheduledTask -Xml failed: $_"
}

# Last-resort fallback: write UTF-16 LE BOM temp file and use schtasks /Create.
if (-not $ok) {
    try {
        $tmp = Join-Path $env:TEMP ("wb_task_" + [guid]::NewGuid().ToString("N") + ".xml")
        [System.IO.File]::WriteAllText($tmp, $xmlString, [System.Text.Encoding]::Unicode)  # UTF-16 LE + BOM
        schtasks /Create /TN $name /XML $tmp /F
        Remove-Item $tmp -Force
        Write-Host "Fallback method (schtasks /Create) succeeded." -ForegroundColor Green
        $ok = $true
    }
    catch {
        Write-Warning "schtasks fallback also failed: $_"
    }
}

if (-not $ok) {
    Write-Error "All registration methods failed."
    exit 1
}

Write-Host ""
Write-Host "=== Task created/updated ===" -ForegroundColor Green
Write-Host "  Triggers : On network connect (EventID 10000)  [instant claim when online]"
Write-Host "            : Daily 09:00 / 12:00 / 15:00 / 18:00 / 21:00  (fallback)"
Write-Host "  Action   : $bat"
Write-Host ""
Write-Host "Verify :  Get-ScheduledTask -TaskName '$name' | Select TaskName, State"
