$ErrorActionPreference='Continue'
"=== reg query exact value ==="
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled
"=== full key dump ==="
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /s
"=== key LastWriteTime (P/Invoke) ==="
$code = @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public class RegTime {
  [DllImport("advapi32.dll", CharSet=CharSet.Auto)]
  public static extern int RegOpenKeyEx(IntPtr hKey, string subKey, int ulOptions, int samDesired, out IntPtr phkResult);
  [DllImport("advapi32.dll", SetLastError=true)]
  public static extern int RegQueryInfoKey(IntPtr hkey, StringBuilder lpClass, IntPtr lpcbClass, IntPtr lpReserved,
     out int lpcSubKeys, out int lpcbMaxSubKeyLen, out int lpcbMaxClassLen, out int lpcValues,
     out int lpcbMaxValueNameLen, out int lpcbMaxValueLen, out int lpcbSecurityDescriptor, out long lpftLastWriteTime);
  public static string GetLastWrite(string subkey) {
    IntPtr hk; long ft;
    IntPtr HKLM = new IntPtr(unchecked((int)0x80000002));
    int r = RegOpenKeyEx(HKLM, subkey, 0, 0x20019, out hk);
    if (r != 0) return "OpenError=" + r;
    int a,b,c,d,e,f,g;
    r = RegQueryInfoKey(hk, null, IntPtr.Zero, IntPtr.Zero, out a, out b, out c, out d, out e, out f, out g, out ft);
    if (r != 0) return "QueryError=" + r;
    return DateTime.FromFileTime(ft).ToString("yyyy-MM-dd HH:mm:ss");
  }
}
'@
Add-Type -TypeDefinition $code -ErrorAction Stop
"AuditKeyLastWriteTime=" + [RegTime]::GetLastWrite('SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit')
"=== effective machine time ==="
Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz'
