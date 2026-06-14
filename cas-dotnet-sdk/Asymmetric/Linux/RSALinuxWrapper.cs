using CasDotnetSdk.Asymmetric.Types;
using CasDotnetSdk.Helpers.Types;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Asymmetric.Linux
{
    internal static class RSALinuxWrapper
    {
        [DllImport("libcas_core_lib.so")]
        public static extern RsaKeyPairStruct get_key_pair(int key_size);

        [DllImport("libcas_core_lib.so")]
        public static extern RsaSignBytesResults rsa_sign_with_key_bytes(string privateKey, byte[] dataToSign, int dataToSignLength);

        [DllImport("libcas_core_lib.so")]
        public static extern CasVerifyResult rsa_verify_bytes(string publicKey, byte[] dataToVerify, int dataToVerifyLength, byte[] signature, int signatureLength);
    }
}
