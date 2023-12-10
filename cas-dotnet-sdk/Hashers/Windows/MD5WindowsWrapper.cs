using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace CasDotnetSdk.Hashers.Windows
{
    internal static class MD5WindowsWrapper
    {
        [DllImport("cas_core_lib.dll")]
        public static extern IntPtr md5_hash_string(string toHash);
        [DllImport("cas_core_lib.dll")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool md5_hash_verify(string hashToVerify, string toHash);
        [DllImport("cas_core_lib.dll")]
        public static extern void free_cstring(IntPtr stringToFree);
    }
}
