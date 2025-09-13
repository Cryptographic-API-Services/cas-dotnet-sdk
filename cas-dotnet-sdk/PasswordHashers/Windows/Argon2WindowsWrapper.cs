using CasDotnetSdk.PasswordHashers.Types;
using System;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.PasswordHashers.Windows
{
    internal static class Argon2WindowsWrapper
    {
        [DllImport("cas_core_lib.dll")]
        public static extern Argon2KDFResult argon2_derive_aes_128_key(string password);

        [DllImport("cas_core_lib.dll")]
        public static extern Argon2KDFResult argon2_derive_aes_256_key(string password);

        [DllImport("cas_core_lib.dll")]
        public static extern IntPtr argon2_hash(string passToHash);

        [DllImport("cas_core_lib.dll")]
        public static extern IntPtr argon2_hash_threadpool(string passToHash);

        [DllImport("cas_core_lib.dll")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool argon2_verify(string hashedPassword, string passToVerify);

        [DllImport("cas_core_lib.dll")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool argon2_verify_threadpool(string hashedPassword, string passToVerify);
    }
}
