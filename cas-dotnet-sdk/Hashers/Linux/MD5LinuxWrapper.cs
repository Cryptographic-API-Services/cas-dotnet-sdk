using System;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Hashers.Linux
{
    internal static class MD5LinuxWrapper
    {
        [DllImport("cas_core_lib.so")]
        public static extern IntPtr md5_hash_string(string toHash);
        [DllImport("cas_core_lib.so")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool md5_hash_verify(string hashToVerify, string toHash);
        [DllImport("cas_core_lib.so")]
        public static extern void free_cstring(IntPtr stringToFree);
    }
}
