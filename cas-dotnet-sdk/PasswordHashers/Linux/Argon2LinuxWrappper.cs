using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using static CasDotnetSdk.PasswordHashers.Argon2Wrappper;

namespace CasDotnetSdk.PasswordHashers.Linux
{
    internal static class Argon2LinuxWrappper
    {

        [DllImport("cas_core_lib.so")]
        public static extern IntPtr argon2_hash(string passToHash);
        [DllImport("cas_core_lib.so")]
        public static extern Argon2ThreadResult argon2_hash_thread(string[] passwordsToHash, int numOfPasswords);
        [DllImport("cas_core_lib.so")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool argon2_verify(string hashedPassword, string passToVerify);
        [DllImport("cas_core_lib.so")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool argon2_verify_thread(string hashedPassword, string passToVerify);
        [DllImport("cas_core_lib.so")]
        public static extern void free_cstring(IntPtr stringToFree);
    }
}
