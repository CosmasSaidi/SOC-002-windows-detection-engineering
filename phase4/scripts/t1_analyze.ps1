$ErrorActionPreference='Continue'
$all = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -ErrorAction SilentlyContinue
"total4688=$($all.Count)"
$empty=0; $nonempty=0; $firstNonEmpty=$null; $lastEmpty=$null
foreach ($e in $all) {
  $x = [xml]$e.ToXml()
  $cl = $null
  foreach ($n in $x.Event.EventData.Data) { if ($n.Name -eq 'CommandLine') { $cl = $n.'#text' } }
  if ([string]::IsNullOrEmpty($cl)) { $empty++; if (-not $lastEmpty) { $lastEmpty = $e.TimeCreated } }
  else { $nonempty++; $firstNonEmpty = $e.TimeCreated }
}
"emptyCommandLine=$empty"
"nonEmptyCommandLine=$nonempty"
"earliestNonEmptyTime=$firstNonEmpty"
"latestEmptyTime=$lastEmpty"
"=== Registry key LastWriteTime via P/Invoke ==="
$code = @"
using System;
using System.Runtime.InteropServices;
using System.Text;
public class RegTime {
  [DllImport("advapi32.dll", CharSet=CharSet.Auto)]
  public static extern int RegOpenKeyEx(IntPtr hKey, string subKey, int ulOptions, int samDesired, out IntPtr phkResult);
  [DllImport("advapi32.dll", SetLastError=true)]
  public static extern int RegQueryInfoKey(IntPtr hkey, StringBuilder lpClass, ref int lpcbClass, IntPtr lpReserved, out int lpcSubKeys, out int lpcbMaxSubKeyLen, out int lpcbMaxClassLen, out int lpcValues, out int lpcbMaxValueNameLen, out int lpcbMaxValueLen, out int lpcbSecurityDescriptor, out long lpftLastWriteTime);
  [DllImport("kernel32.dll")]
  public static extern int GetSystemTimeAsFileTime(out long lpSystemTimeAsFileTime);
  public static DateTime GetLastWrite(string subkey) {
    IntPtr hk; long ft;
    IntPtr HKLM = new IntPtr(unchecked((int)0x80000002));
    int r = RegOpenKeyEx(HKLM, subkey, 0, 0x20019, out hk);
    if (r != 0) return DateTime.MinValue;
    int a,b,c,d,e,f,g;
    r = RegQueryInfoKey(hk, null, ref (new int()), IntPtr.Zero, out a, out b, out c, out d, out e, out f, out g, out ft);
    if (r != 0) return DateTime.MinValue;
    return DateTime.FromFileTime(ft);
  }
}
"@
Add-Type -TypeDefinition $code -ErrorAction SilentlyContinue
$t = [RegTime]::GetLastWrite('SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit')
"AuditKeyLastWriteTime=$t"
