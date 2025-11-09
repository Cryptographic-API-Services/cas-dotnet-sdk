using CasDotnetSdk.DigitalSignature.Types;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.DigitalSignature.Windows
{
    internal static class DigitalSignatureWindowsWrapper
    {
        [DllImport("cas_core_lib.dll")]
        public static extern SHARSAStructDigitialSignatureResult sha_512_rsa_digital_signature(int rsaKeySize, byte[] dataToSign, int dataLength);

        [DllImport("cas_core_lib.dll")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool sha_512_rsa_digital_signature_verify(string publicKey, byte[] dataToVerify, int dataToVerifyLength, byte[] signature, int signatureLength);

        [DllImport("cas_core_lib.dll")]
        public static extern SHARSAStructDigitialSignatureResult sha_256_rsa_digital_signature(int rsaKeySize, byte[] dataToSign, int dataLength);

        [DllImport("cas_core_lib.dll")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool sha_256_rsa_digital_signature_verify(string publicKey, byte[] dataToVerify, int dataToVerifyLength, byte[] signature, int signatureLength);
    }
}
