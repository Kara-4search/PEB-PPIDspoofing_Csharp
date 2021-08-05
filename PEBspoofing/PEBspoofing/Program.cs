using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Diagnostics;

namespace PEBspoofing
{

    class Program
    {
        public static int FindProcessIDByName(string processname)
        {
            int processpid = 0;

            Process[] processlist = Process.GetProcesses();

            foreach (Process p in processlist)
            {
                // Console.WriteLine("Process: {0} ID: {1}", p.ProcessName, p.Id);
                if (p.ProcessName.ToLower() == processname)
                {
                    // Console.WriteLine("Find: {0}", p.Id);
                    // System.Threading.Thread.Sleep(50000);
                    processpid = p.Id;
                    return processpid;
                }
                // System.Threading.Thread.Sleep(100);
            }
            return processpid;
        }

        static void Main(string[] args)
        {
            int processpid = FindProcessIDByName("explorer");
            // Console.WriteLine(processpid);
            // System.Threading.Thread.Sleep(50000);
            if (processpid != 0)
            {
                ProcessCreator.CreateProcess(processpid);
            }
            
            //IntPtr test = IntPtr.Zero;
            //Char[] arrayC = new char[64];
            //ProcessCreator.CURDIR test = new ProcessCreator.CURDIR();
            //Console.WriteLine(Marshal.SizeOf(test));
            //System.Threading.Thread.Sleep(10000);
        }
    }
}
