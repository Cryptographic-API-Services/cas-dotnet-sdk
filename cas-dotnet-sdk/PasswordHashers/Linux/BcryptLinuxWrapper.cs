using System;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.PasswordHashers.Linux
{
    internal static class BcryptLinuxWrapper
    {
        [DllImport("Contents/libcas_core_lib.so")]
        public static extern IntPtr bcrypt_hash(string passToHash);

        [DllImport("Contents/libcas_core_lib.so")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool bcrypt_verify(string password, string hash);
        [DllImport("Contents/libcas_core_lib.so")]
        public static extern void free_cstring(IntPtr stringToFree);
    }
}
