using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace CasDotnetSdk.Hashers.Linux
{
    internal static class MD5LinuxWrapper
    {
        [DllImport("performant_encryption.so")]
        public static extern IntPtr md5_hash_string(string toHash);
        [DllImport("performant_encryption.so")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool md5_hash_verify(string hashToVerify, string toHash);
        [DllImport("performant_encryption.so")]
        public static extern void free_cstring(IntPtr stringToFree);
    }
}
