using CasDotnetSdk.Helpers.Types;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.PasswordHashers.Windows
{
    internal static class BcryptWindowsWrapper
    {
        [DllImport("cas_core_lib.dll")]
        public static extern CasStringResult bcrypt_hash(string passToHash);

        [DllImport("cas_core_lib.dll")]
        public static extern CasVerifyResult bcrypt_verify(string password, string hash);

        [DllImport("cas_core_lib.dll")]
        public static extern CasStringResult bcrypt_hash_with_parameters(string passToHash, uint cost);
    }
}
