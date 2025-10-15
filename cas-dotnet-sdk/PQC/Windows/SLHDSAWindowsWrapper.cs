using CasDotnetSdk.PQC.Types;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.PQC.Windows
{
    internal class SLHDSAWindowsWrapper
    {
        [DllImport("cas_core_lib.dll")]
        public static extern SLHDSAKeyPairStruct slh_dsa_generate_signing_and_verification_key();

        [DllImport("cas_core_lib.dll")]
        public static extern SLHDSASignatureStruct slh_dsa_sign_message(byte[] signingKey, int signingKeyLength, byte[] message, int messageLength);

        [DllImport("cas_core_lib.dll")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool slh_dsa_verify_signature(byte[] verificationKey, int verificationKeyLength, byte[] signature, int signatureLength, byte[] message, int messageLength);
    }
}
