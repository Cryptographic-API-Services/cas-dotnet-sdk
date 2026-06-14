using CasDotnetSdk.Helpers.Types;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.PasswordHashers.Linux
{
    internal static class SCryptLinuxWrapper
    {
        [DllImport("libcas_core_lib.so")]
        public static extern CasStringResult scrypt_hash(string passToHash);

        [DllImport("libcas_core_lib.so")]
        public static extern CasVerifyResult scrypt_verify(string hashedPassword, string password);

        [DllImport("libcas_core_lib.so")]
        public static extern CasStringResult scrypt_hash_with_parameters(string passToHash, int cpuCost, int blockSize, int paralelism);
    }
}
