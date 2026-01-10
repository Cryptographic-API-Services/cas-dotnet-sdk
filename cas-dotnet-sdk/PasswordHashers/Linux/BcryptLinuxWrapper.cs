using System;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.PasswordHashers.Linux
{
    internal static class BcryptLinuxWrapper
    {
        [DllImport("libcas_core_lib.so")]
        public static extern IntPtr bcrypt_hash(string passToHash);

        [DllImport("libcas_core_lib.so")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool bcrypt_verify(string password, string hash);

        [DllImport("libcas_core_lib.so")]
        public static extern IntPtr bcrypt_hash_with_parameters(string passToHash, uint cost);
    }
}
