using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using static CasDotnetSdk.DigitalSignature.DigitalSignatureWrapper;

namespace CasDotnetSdk.DigitalSignature.Windows
{
    internal static class DigitalSignatureWindowsWrapper
    {
        [DllImport("cas_core_lib.dll")]
        public static extern SHARSADigitialSignatureResult sha_512_rsa_digital_signature(int rsaKeySize, byte[] dataToSign, int dataLength);

        [DllImport("cas_core_lib.dll")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool sha_512_rsa_digital_signature_verify(string publicKey, byte[] dataToVerify, int dataToVerifyLength, byte[] signature, int signatureLength);

        [DllImport("cas_core_lib.dll")]
        public static extern void free_cstring(IntPtr stringToFree);

        [DllImport("cas_core_lib.dll")]
        public static extern void free_bytes(IntPtr bytesToFree);
    }
}
