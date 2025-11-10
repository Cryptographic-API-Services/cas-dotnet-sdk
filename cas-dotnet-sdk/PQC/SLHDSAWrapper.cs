using CasDotnetSdk.Helpers;
using CasDotnetSdk.PQC.Linux;
using CasDotnetSdk.PQC.Types;
using CasDotnetSdk.PQC.Windows;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.PQC
{
    public class SLHDSAWrapper : BaseWrapper
    {
        public SLHDSAWrapper()
        {

        }
        public SLHDSAKeyPair GenerateSigningAndVerificationKey()
        {
            SLHDSAKeyPairStruct result = (this._platform == OSPlatform.Linux) ? SLHDSALinuxWrapper.slh_dsa_generate_signing_and_verification_key() : SLHDSAWindowsWrapper.slh_dsa_generate_signing_and_verification_key();
            byte[] signingKey = new byte[result.signing_key_length];
            Marshal.Copy(result.signing_key_ptr, signingKey, 0, result.signing_key_length);
            FreeMemoryHelper.FreeBytesMemory(result.signing_key_ptr);

            byte[] verificationKey = new byte[result.verification_key_length];
            Marshal.Copy(result.verification_key_ptr, verificationKey, 0, result.verification_key_length);
            FreeMemoryHelper.FreeBytesMemory(result.verification_key_ptr);
            return new SLHDSAKeyPair
            {
                SigningKey = signingKey,
                VerificationKey = verificationKey
            };
        }

        public byte[] Sign(byte[] signingKey, byte[] message)
        {
            SLHDSASignatureStruct result = (this._platform == OSPlatform.Linux) ? SLHDSALinuxWrapper.slh_dsa_sign_message(signingKey, signingKey.Length, message, message.Length) : SLHDSAWindowsWrapper.slh_dsa_sign_message(signingKey, signingKey.Length, message, message.Length);
            byte[] signature = new byte[result.signature_length];
            Marshal.Copy(result.signature_ptr, signature, 0, result.signature_length);
            FreeMemoryHelper.FreeBytesMemory(result.signature_ptr);
            return signature;
        }

        public bool Verify(byte[] verificationKey, byte[] signature, byte[] message)
        {
            return (this._platform == OSPlatform.Linux) ? SLHDSALinuxWrapper.slh_dsa_verify_signature(verificationKey, verificationKey.Length, signature, signature.Length, message, message.Length) : SLHDSAWindowsWrapper.slh_dsa_verify_signature(verificationKey, verificationKey.Length, signature, signature.Length, message, message.Length);
        }
    }
}
