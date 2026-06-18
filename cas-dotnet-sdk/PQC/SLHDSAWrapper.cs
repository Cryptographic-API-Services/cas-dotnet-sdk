using CasCoreLib;
using CasDotnetSdk.Helpers;
using CasDotnetSdk.PQC.Types;

namespace CasDotnetSdk.PQC
{
    public unsafe class SLHDSAWrapper : BaseWrapper
    {
        public SLHDSAWrapper()
        {
        }

        public SLHDSAKeyPair GenerateSigningAndVerificationKey()
        {
            SlhDsaKeyPairResult result = NativeMethods.slh_dsa_generate_signing_and_verification_key();
            return new SLHDSAKeyPair
            {
                SigningKey = NativeByteBuffer.CopyAndFree(result.signing_key_ptr, result.signing_key_length),
                VerificationKey = NativeByteBuffer.CopyAndFree(result.verification_key_ptr, result.verification_key_length)
            };
        }

        public byte[] Sign(byte[] signingKey, byte[] message)
        {
            fixed (byte* signingKeyPtr = NativePin.Of(signingKey))
            fixed (byte* messagePtr = NativePin.Of(message))
            {
                SlhDsaSignature result = NativeMethods.slh_dsa_sign_message(signingKeyPtr, (nuint)signingKey.Length, messagePtr, (nuint)message.Length);
                CasErrorHandler.ThrowIfError(result.error_code, "SLH-DSA sign");
                return NativeByteBuffer.CopyAndFree(result.signature_ptr, result.signature_length);
            }
        }

        public bool Verify(byte[] verificationKey, byte[] signature, byte[] message)
        {
            fixed (byte* verificationKeyPtr = NativePin.Of(verificationKey))
            fixed (byte* signaturePtr = NativePin.Of(signature))
            fixed (byte* messagePtr = NativePin.Of(message))
            {
                CasVerifyResult result = NativeMethods.slh_dsa_verify_signature(verificationKeyPtr, (nuint)verificationKey.Length, signaturePtr, (nuint)signature.Length, messagePtr, (nuint)message.Length);
                CasErrorHandler.ThrowIfError(result.error_code, "SLH-DSA verify");
                return result.is_valid;
            }
        }
    }
}
