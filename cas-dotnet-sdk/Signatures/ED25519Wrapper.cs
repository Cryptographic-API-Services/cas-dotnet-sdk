using CasCoreLib;
using CasDotnetSdk.Helpers;
using CasDotnetSdk.Signatures.Types;
using System;

// Both CasCoreLib (native) and CasDotnetSdk.Signatures.Types (public) define a
// type named Ed25519ByteSignatureResult. Pin the unqualified name to the public
// one; the native struct is referenced fully-qualified below.
using Ed25519ByteSignatureResult = CasDotnetSdk.Signatures.Types.Ed25519ByteSignatureResult;

namespace CasDotnetSdk.Signatures
{
    /// <summary>
    /// Ed25519 (RFC 8032) signatures over ed25519-dalek. Both verify methods use strict
    /// verification (<c>verify_strict</c>): they reject non-canonical encodings,
    /// small-order R components and small-order (weak) public keys, so a signature that one
    /// method accepts the other accepts too.
    /// </summary>
    public unsafe class ED25519Wrapper 
    {
        public ED25519Wrapper()
        {
        }

        /// <summary>
        /// Generates an Ed25519 key pair: a 32-byte <see cref="Ed25519KeyPairResult.SigningKey"/>
        /// (the secret seed; keep it private) and a 32-byte <see cref="Ed25519KeyPairResult.VerifyingKey"/>
        /// (the public key to share with verifiers).
        /// </summary>
        public Ed25519KeyPairResult GetKeyPair()
        {
            Ed25519KeyPairBytesResult result = NativeMethods.get_ed25519_key_pair_bytes();
            try
            {
                CasErrorHandler.ThrowIfError(result.error_code, "ED25519 key generation");
                return new Ed25519KeyPairResult()
                {
                    SigningKey = NativeByteBuffer.Copy(result.signing_key, result.signing_key_length),
                    VerifyingKey = NativeByteBuffer.Copy(result.verifying_key, result.verifying_key_length)
                };
            }
            finally
            {
                NativeMethods.free_ed25519_key_pair_bytes_result(&result);
            }
        }

        /// <summary>
        /// Signs data with an Ed25519 signing key. The result carries the 64-byte signature and the
        /// 32-byte public key that verifies it with <see cref="VerifyWithPublicKeyBytes"/>.
        /// </summary>
        /// <param name="keyBytes">The 32-byte signing key from <see cref="GetKeyPair"/>.</param>
        /// <param name="dataToSign">The message to sign.</param>
        public Ed25519ByteSignatureResult SignBytes(byte[] keyBytes, byte[] dataToSign)
        {
            if (keyBytes == null || keyBytes.Length == 0)
            {
                throw new Exception("You must provide an array allocated with key data to Sign with ED25519-Dalek");
            }
            if (dataToSign == null || dataToSign.Length == 0)
            {
                throw new Exception("You must provide an array allocated with data to Sign with ED25519-Dalek");
            }

            fixed (byte* keyPtr = NativePin.Of(keyBytes))
            fixed (byte* dataPtr = NativePin.Of(dataToSign))
            {
                CasCoreLib.Ed25519ByteSignatureResult result = NativeMethods.sign_with_key_pair_bytes(keyPtr, (nuint)keyBytes.Length, dataPtr, (nuint)dataToSign.Length);
                try
                {
                    CasErrorHandler.ThrowIfError(result.error_code, "ED25519 sign");
                    return new CasDotnetSdk.Signatures.Types.Ed25519ByteSignatureResult()
                    {
                        PublicKey = NativeByteBuffer.Copy(result.public_key, result.public_key_length),
                        Signature = NativeByteBuffer.Copy(result.signature_byte_ptr, result.signature_length)
                    };
                }
                finally
                {
                    NativeMethods.free_ed25519_byte_signature_result(&result);
                }
            }
        }

        /// <summary>
        /// Verifies an Ed25519 signature with the <em>signing</em> key, deriving the public key from it.
        /// Deprecated: a verifier should never need the signing key. Use
        /// <see cref="VerifyWithPublicKeyBytes"/> with the public key instead. Verification is strict
        /// and gives the same result as <see cref="VerifyWithPublicKeyBytes"/>.
        /// </summary>
        /// <param name="keyPair">The 32-byte signing key from <see cref="GetKeyPair"/>.</param>
        /// <param name="signature">The 64-byte signature to check.</param>
        /// <param name="dataToVerify">The message that was signed.</param>
        [Obsolete("VerifyBytes takes the signing key, so verifiers would hold signing keys. Use VerifyWithPublicKeyBytes(publicKey, signature, dataToVerify) with the public key instead.")]
        public bool VerifyBytes(byte[] keyPair, byte[] signature, byte[] dataToVerify)
        {
            if (keyPair == null || keyPair.Length == 0)
            {
                throw new Exception("You must provide allocated key pair data to Verify Bytes with ED25519-Dalek");
            }
            if (signature == null || signature.Length == 0)
            {
                throw new Exception("You must provide allocated signature data to Verify Bytes with ED25519-Dalek");
            }
            if (dataToVerify == null || dataToVerify.Length == 0)
            {
                throw new Exception("You must provide allocated data to Verify with ED25519-Dalek");
            }

            fixed (byte* keyPtr = NativePin.Of(keyPair))
            fixed (byte* signaturePtr = NativePin.Of(signature))
            fixed (byte* dataPtr = NativePin.Of(dataToVerify))
            {
                CasVerifyResult result = NativeMethods.verify_with_key_pair_bytes(keyPtr, (nuint)keyPair.Length, signaturePtr, (nuint)signature.Length, dataPtr, (nuint)dataToVerify.Length);
                CasErrorHandler.ThrowIfError(result.error_code, "ED25519 verify");
                return result.is_valid;
            }
        }

        /// <summary>
        /// Verifies an Ed25519 signature with the signer's public key. This is the method to use for
        /// verification. It is strict (<c>verify_strict</c>): non-canonical signatures, small-order
        /// R components and small-order public keys are rejected.
        /// </summary>
        /// <param name="publicKey">The signer's 32-byte public key (<see cref="Ed25519KeyPairResult.VerifyingKey"/>
        /// or <see cref="Ed25519ByteSignatureResult.PublicKey"/>).</param>
        /// <param name="signature">The 64-byte signature to check.</param>
        /// <param name="dataToVerify">The message that was signed.</param>
        /// <returns><c>true</c> if the signature is valid for the message and key; otherwise <c>false</c>.</returns>
        public bool VerifyWithPublicKeyBytes(byte[] publicKey, byte[] signature, byte[] dataToVerify)
        {
            if (publicKey == null || publicKey.Length == 0)
            {
                throw new Exception("You must provide allocated data for the public key to verify with ED25519-Dalek");
            }
            if (signature == null || signature.Length == 0)
            {
                throw new Exception("You must provide allocated data for the signature to verify with ED25519-Dalek");
            }
            if (dataToVerify == null || dataToVerify.Length == 0)
            {
                throw new Exception("You must provide allocated data to verify for the signature to verify with ED25519-Dalek");
            }

            fixed (byte* publicPtr = NativePin.Of(publicKey))
            fixed (byte* signaturePtr = NativePin.Of(signature))
            fixed (byte* dataPtr = NativePin.Of(dataToVerify))
            {
                CasVerifyResult result = NativeMethods.verify_with_public_key_bytes(publicPtr, (nuint)publicKey.Length, signaturePtr, (nuint)signature.Length, dataPtr, (nuint)dataToVerify.Length);
                CasErrorHandler.ThrowIfError(result.error_code, "ED25519 verify");
                return result.is_valid;
            }
        }
    }
}
