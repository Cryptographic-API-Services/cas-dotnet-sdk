using CasDotnetSdk.PasswordHashers.Types;
using System;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.PasswordHashers.Linux
{
    internal static class Argon2LinuxWrapper
    {

        [DllImport("Contents\\libcas_core_lib.so")]
        public static extern IntPtr argon2_hash(string passToHash);
        [DllImport("Contents\\libcas_core_lib.so")]
        public static extern Argon2ThreadResult argon2_hash_thread(string[] passwordsToHash, int numOfPasswords);
        [DllImport("Contents\\libcas_core_lib.so")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool argon2_verify(string hashedPassword, string passToVerify);
        [DllImport("Contents\\libcas_core_lib.so")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool argon2_verify_thread(string hashedPassword, string passToVerify);
        [DllImport("Contents\\libcas_core_lib.so")]
        public static extern void free_cstring(IntPtr stringToFree);
    }
}
