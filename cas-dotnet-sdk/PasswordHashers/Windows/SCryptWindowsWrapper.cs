using System;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.PasswordHashers.Windows
{
    internal static class SCryptWindowsWrapper
    {
        [DllImport("cas_core_lib.dll")]
        public static extern IntPtr scrypt_hash(string passToHash);

        [DllImport("cas_core_lib.dll")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool scrypt_verify(string hashedPassword, string password);

        [DllImport("cas_core_lib.dll")]
        public static extern IntPtr scrypt_hash_with_parameters(string passToHash, int cpuCost, int blockSize, int paralelism);
    }
}
