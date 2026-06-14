using CasDotnetSdk.Helpers.Types;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.PasswordHashers.Linux
{
    internal static class BcryptLinuxWrapper
    {
        [DllImport("libcas_core_lib.so")]
        public static extern CasStringResult bcrypt_hash(string passToHash);

        [DllImport("libcas_core_lib.so")]
        public static extern CasVerifyResult bcrypt_verify(string password, string hash);

        [DllImport("libcas_core_lib.so")]
        public static extern CasStringResult bcrypt_hash_with_parameters(string passToHash, uint cost);
    }
}
