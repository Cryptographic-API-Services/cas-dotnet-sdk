using CasDotnetSdk.Hashers.Types;
using CasDotnetSdk.Helpers.Types;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Hashers.Windows
{
    internal static class HmacWindowsWrapper
    {
        [DllImport("cas_core_lib.dll")]
        public static extern HmacSignByteResult hmac_sign_bytes(byte[] key, int keyLength, byte[] message, int messageLength);

        [DllImport("cas_core_lib.dll")]
        public static extern CasVerifyResult hmac_verify_bytes(byte[] key, int keyLength, byte[] message, int messageLength, byte[] signature, int signatureLength);
    }
}
