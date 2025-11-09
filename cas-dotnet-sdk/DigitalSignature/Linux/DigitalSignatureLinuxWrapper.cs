using CasDotnetSdk.DigitalSignature.Types;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.DigitalSignature.Linux
{
    internal static class DigitalSignatureLinuxWrapper
    {
        [DllImport("libcas_core_lib.so")]
        public static extern SHARSAStructDigitialSignatureResult sha_512_rsa_digital_signature(int rsaKeySize, byte[] dataToSign, int dataLength);

        [DllImport("libcas_core_lib.so")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool sha_512_rsa_digital_signature_verify(string publicKey, byte[] dataToVerify, int dataToVerifyLength, byte[] signature, int signatureLength);

        [DllImport("libcas_core_lib.so")]
        public static extern SHARSAStructDigitialSignatureResult sha_256_rsa_digital_signature(int rsaKeySize, byte[] dataToSign, int dataLength);

        [DllImport("libcas_core_lib.so")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool sha_256_rsa_digital_signature_verify(string publicKey, byte[] dataToVerify, int dataToVerifyLength, byte[] signature, int signatureLength);
    }
}
