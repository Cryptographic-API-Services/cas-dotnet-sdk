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
    public unsafe class ED25519Wrapper 
    {
        public ED25519Wrapper()
        {
        }

        /// <summary>
        /// Generates and public and private key pair non split in bytes for ED25519-Dalek.
        /// </summary>
        public Ed25519KeyPairResult GetKeyPair()
        {
            Ed25519KeyPairBytesResult result = NativeMethods.get_ed25519_key_pair_bytes();
            return new Ed25519KeyPairResult()
            {
                SigningKey = NativeByteBuffer.CopyAndFree(result.signing_key, result.signing_key_length),
                VerifyingKey = NativeByteBuffer.CopyAndFree(result.verifying_key, result.verifying_key_length)
            };
        }

        /// <summary>
        /// Signs data with a key pair in bytes for ED25519-Dalek.
        /// </summary>
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
                CasErrorHandler.ThrowIfError(result.error_code, "ED25519 sign");
                return new CasDotnetSdk.Signatures.Types.Ed25519ByteSignatureResult()
                {
                    PublicKey = NativeByteBuffer.CopyAndFree(result.public_key, result.public_key_length),
                    Signature = NativeByteBuffer.CopyAndFree(result.signature_byte_ptr, result.signature_length)
                };
            }
        }

        /// <summary>
        /// Verifys data with a key pair in bytes for ED25519-Dalek.
        /// </summary>
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
        /// Verifies with a public key in bytes for ED25519-Dalek.
        /// </summary>
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
