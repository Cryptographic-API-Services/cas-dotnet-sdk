using System;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.PasswordHashers.Linux
{
    internal static class BcryptLinuxWrapper
    {
        [DllImport("cas_core_lib.so")]
        public static extern IntPtr bcrypt_hash(string passToHash);

        [DllImport("cas_core_lib.so")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool bcrypt_verify(string password, string hash);
        [DllImport("cas_core_lib.so")]
        public static extern void free_cstring(IntPtr stringToFree);
    }
}
