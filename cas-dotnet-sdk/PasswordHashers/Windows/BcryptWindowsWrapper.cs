using System;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.PasswordHashers.Windows
{
    internal static class BcryptWindowsWrapper
    {
        [DllImport("\\Contents\\cas_core_lib.dll")]
        public static extern IntPtr bcrypt_hash(string passToHash);

        [DllImport("\\Contents\\cas_core_lib.dll")]
        public static extern IntPtr bcrypt_hash_threadpool(string passToHash);

        [DllImport("\\Contents\\cas_core_lib.dll")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool bcrypt_verify(string password, string hash);
        [DllImport("\\Contents\\cas_core_lib.dll")]
        public static extern void free_cstring(IntPtr stringToFree);
    }
}
