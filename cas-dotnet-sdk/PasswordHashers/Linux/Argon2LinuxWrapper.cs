using CasDotnetSdk.PasswordHashers.Types;
using System;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.PasswordHashers.Linux
{
    internal static class Argon2LinuxWrapper
    {
        [DllImport("libcas_core_lib.so")]
        public static extern Argon2KDFResult argon2_derive_aes_128_key(string password);

        [DllImport("libcas_core_lib.so")]
        public static extern Argon2KDFResult argon2_derive_aes_256_key(string password);

        [DllImport("libcas_core_lib.so")]
        public static extern IntPtr argon2_hash(string passToHash);

        [DllImport("libcas_core_lib.so")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool argon2_verify(string hashedPassword, string passToVerify);

        [DllImport("libcas_core_lib.so")]
        public static extern IntPtr argon2_hash_password_parameters(int memoryCost, int iterations, int parallelism, string passToHash);
    }
}
