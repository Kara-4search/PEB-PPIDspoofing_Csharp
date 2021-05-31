using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace PEBspoofing
{

    class Program
    {
        static void Main(string[] args)
        {
            int processpid = 6344;
            ProcessCreator.CreateProcess(processpid);
            //IntPtr test = IntPtr.Zero;
            //Char[] arrayC = new char[64];
            //ProcessCreator.CURDIR test = new ProcessCreator.CURDIR();
            //Console.WriteLine(Marshal.SizeOf(test));
            //System.Threading.Thread.Sleep(10000);
        }
    }
}
