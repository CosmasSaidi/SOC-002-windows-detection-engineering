$ErrorActionPreference='Continue'
"=== HOST ==="
$env:COMPUTERNAME
"=== OS ==="
(Get-CimInstance Win32_OperatingSystem).Caption
"=== KEY: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit ==="
$k='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
if (Test-Path $k) {
  Get-ItemProperty -Path $k | Select-Object -Property * -ExcludeProperty PS* | Format-List | Out-String
  "ProcessCreationIncludeCmdLine_Enabled value: " + (Get-ItemProperty -Path $k -Name ProcessCreationIncludeCmdLine_Enabled -ErrorAction SilentlyContinue).ProcessCreationIncludeCmdLine_Enabled
} else { "PATH NOT PRESENT: $k" }
"=== KEY: HKLM\SOFTWARE\Policies\Microsoft\Windows\System (AuditProcessCreation) ==="
Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -ErrorAction SilentlyContinue | Select-Object AuditProcessCreation* | Format-List | Out-String
"=== auditpol Process Creation ==="
auditpol /get /subcategory:"Process Creation"
"=== auditpol Detailed Tracking overview ==="
auditpol /get /category:"Detailed Tracking"
