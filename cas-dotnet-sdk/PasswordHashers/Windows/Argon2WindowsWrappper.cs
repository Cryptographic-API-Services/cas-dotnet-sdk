using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using static CasDotnetSdk.PasswordHashers.Argon2Wrappper;

namespace CasDotnetSdk.PasswordHashers.Windows
{
    internal static class Argon2WindowsWrappper
    {

        [DllImport("cas_core_lib.dll")]
        public static extern IntPtr argon2_hash(string passToHash);
        [DllImport("cas_core_lib.dll")]
        public static extern Argon2ThreadResult argon2_hash_thread(string[] passwordsToHash, int numOfPasswords);
        [DllImport("cas_core_lib.dll")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool argon2_verify(string hashedPassword, string passToVerify);
        [DllImport("cas_core_lib.dll")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool argon2_verify_thread(string hashedPassword, string passToVerify);
        [DllImport("cas_core_lib.dll")]
        public static extern void free_cstring(IntPtr stringToFree);
    }
}
