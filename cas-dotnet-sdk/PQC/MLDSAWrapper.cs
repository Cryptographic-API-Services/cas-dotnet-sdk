using CasCoreLib;
using CasDotnetSdk.Helpers;
using CasDotnetSdk.PQC.Types;

namespace CasDotnetSdk.PQC
{
    /// <summary>
    /// ML-DSA-65 (FIPS 204) post-quantum digital signatures. Signing is deterministic
    /// and uses an empty context.
    /// </summary>
    public unsafe class MLDSAWrapper
    {
        public MLDSAWrapper()
        {
        }

        /// <summary>
        /// Generates an ML-DSA-65 signing (32-byte seed) and verification (1952-byte) key pair.
        /// </summary>
        public MLDSAKeyPair GenerateSigningAndVerificationKey()
        {
            MlDsaKeyPairResult result = NativeMethods.ml_dsa_generate_signing_and_verification_key();
            return new MLDSAKeyPair
            {
                SigningKey = NativeByteBuffer.CopyAndFree(result.signing_key_ptr, result.signing_key_length),
                VerificationKey = NativeByteBuffer.CopyAndFree(result.verification_key_ptr, result.verification_key_length)
            };
        }

        /// <summary>
        /// Signs <paramref name="message"/> with an ML-DSA-65 signing key, returning the 3309-byte signature.
        /// </summary>
        /// <param name="signingKey">The 32-byte ML-DSA-65 signing key.</param>
        /// <param name="message">The message bytes to sign.</param>
        public byte[] Sign(byte[] signingKey, byte[] message)
        {
            fixed (byte* signingKeyPtr = NativePin.Of(signingKey))
            fixed (byte* messagePtr = NativePin.Of(message))
            {
                MlDsaSignature result = NativeMethods.ml_dsa_sign_message(signingKeyPtr, (nuint)signingKey.Length, messagePtr, (nuint)message.Length);
                CasErrorHandler.ThrowIfError(result.error_code, "ML-DSA sign");
                return NativeByteBuffer.CopyAndFree(result.signature_ptr, result.signature_length);
            }
        }

        /// <summary>
        /// Verifies an ML-DSA-65 <paramref name="signature"/> over <paramref name="message"/>.
        /// </summary>
        /// <param name="verificationKey">The 1952-byte ML-DSA-65 verification key.</param>
        /// <param name="signature">The signature to verify.</param>
        /// <param name="message">The message the signature is expected to cover.</param>
        public bool Verify(byte[] verificationKey, byte[] signature, byte[] message)
        {
            fixed (byte* verificationKeyPtr = NativePin.Of(verificationKey))
            fixed (byte* signaturePtr = NativePin.Of(signature))
            fixed (byte* messagePtr = NativePin.Of(message))
            {
                CasVerifyResult result = NativeMethods.ml_dsa_verify_signature(verificationKeyPtr, (nuint)verificationKey.Length, signaturePtr, (nuint)signature.Length, messagePtr, (nuint)message.Length);
                CasErrorHandler.ThrowIfError(result.error_code, "ML-DSA verify");
                return result.is_valid;
            }
        }
    }
}
