using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace CasDotnetSdk.Hashers.Linux
{
    internal static class SHALinuxWrapper
    {

        [DllImport("performant_encryption.dll")]
        public static extern IntPtr sha512(string password);
        [DllImport("performant_encryption.dll")]
        public static extern IntPtr sha256(string password);
        [DllImport("performant_encryption.dll")]
        public static extern void free_cstring(IntPtr stringToFree);
    }
}
