using CasCoreLib;
using CasDotnetSdk.Helpers;
using CasDotnetSdk.PQC.Types;

namespace CasDotnetSdk.PQC
{
    /// <summary>
    /// SLH-DSA-SHAKE-128f (FIPS 205, the fast "f" variant of the stateless hash-based signature
    /// scheme over SHAKE-128). Signing is deterministic and uses an empty context. Signatures are
    /// large (17,088 bytes) but rely only on hash-function security.
    /// </summary>
    public unsafe class SLHDSAWrapper 
    {
        public SLHDSAWrapper()
        {
        }

        /// <summary>
        /// Generates an SLH-DSA-SHAKE-128f signing (64-byte) and verification (32-byte) key pair.
        /// </summary>
        public SLHDSAKeyPair GenerateSigningAndVerificationKey()
        {
            SlhDsaKeyPairResult result = NativeMethods.slh_dsa_generate_signing_and_verification_key();
            try
            {
                CasErrorHandler.ThrowIfError(result.error_code, "SLH-DSA key generation");
                return new SLHDSAKeyPair
                {
                    SigningKey = NativeByteBuffer.Copy(result.signing_key_ptr, result.signing_key_length),
                    VerificationKey = NativeByteBuffer.Copy(result.verification_key_ptr, result.verification_key_length)
                };
            }
            finally
            {
                NativeMethods.free_slh_dsa_key_pair_result(&result);
            }
        }

        /// <summary>
        /// Signs <paramref name="message"/> with an SLH-DSA-SHAKE-128f signing key, returning the 17,088-byte signature.
        /// </summary>
        /// <param name="signingKey">The 64-byte SLH-DSA-SHAKE-128f signing key.</param>
        /// <param name="message">The message bytes to sign.</param>
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

        /// <summary>
        /// Verifies an SLH-DSA-SHAKE-128f <paramref name="signature"/> over <paramref name="message"/>.
        /// </summary>
        /// <param name="verificationKey">The 32-byte SLH-DSA-SHAKE-128f verification key.</param>
        /// <param name="signature">The signature to verify.</param>
        /// <param name="message">The message the signature is expected to cover.</param>
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
