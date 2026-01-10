using System;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.PasswordHashers.Linux
{
    internal static class SCryptLinuxWrapper
    {
        [DllImport("libcas_core_lib.so")]
        public static extern IntPtr scrypt_hash(string passToHash);

        [DllImport("libcas_core_lib.so")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool scrypt_verify(string hashedPassword, string password);

        [DllImport("libcas_core_lib.so")]
        public static extern IntPtr scrypt_hash_with_parameters(string passToHash, int cpuCost, int blockSize, int paralelism);
    }
}
