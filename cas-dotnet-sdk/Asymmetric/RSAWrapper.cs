using CasCoreLib;
using CasDotnetSdk.Asymmetric.Types;
using CasDotnetSdk.Helpers;
using System;

namespace CasDotnetSdk.Asymmetric
{
    public unsafe class RSAWrapper 
    {
        /// <summary>
        /// A wrapper class for RSA key creation, encryption, decryption, signing, and verification.
        /// </summary>
        public RSAWrapper()
        {
        }

        /// <summary>
        /// Signs data with an RSA private key.
        /// </summary>
        public byte[] Sign(string privateKey, byte[] dataToSign)
        {
            if (dataToSign == null || dataToSign.Length == 0)
            {
                throw new Exception("You must provide allocated data to sign with RSA");
            }

            fixed (byte* privateKeyPtr = NativeString.ToCString(privateKey))
            fixed (byte* dataPtr = NativePin.Of(dataToSign))
            {
                RsaSignBytesResults signResult = NativeMethods.rsa_sign_with_key_bytes(privateKeyPtr, dataPtr, (nuint)dataToSign.Length);
                CasErrorHandler.ThrowIfError(signResult.error_code, "RSA sign");
                return NativeByteBuffer.CopyAndFree(signResult.signature_raw_ptr, signResult.length);
            }
        }

        /// <summary>
        /// Verifies data with an RSA public key.
        /// </summary>
        public bool Verify(string publicKey, byte[] dataToVerify, byte[] signature)
        {
            if (dataToVerify == null || dataToVerify.Length == 0)
            {
                throw new Exception("You must provide allocated data to verify with RSA");
            }
            if (signature == null || signature.Length == 0)
            {
                throw new Exception("You must provide an allocated signature to verify with RSA");
            }

            fixed (byte* publicKeyPtr = NativeString.ToCString(publicKey))
            fixed (byte* dataPtr = NativePin.Of(dataToVerify))
            fixed (byte* signaturePtr = NativePin.Of(signature))
            {
                CasVerifyResult result = NativeMethods.rsa_verify_bytes(publicKeyPtr, dataPtr, (nuint)dataToVerify.Length, signaturePtr, (nuint)signature.Length);
                CasErrorHandler.ThrowIfError(result.error_code, "RSA verify");
                return result.is_valid;
            }
        }

        /// <summary>
        /// Generates an RSA key based on the key size provided. (1024, 2048, 4096)
        /// </summary>
        public RsaKeyPairResult GetKeyPair(int keySize)
        {
            if (keySize != 1024 && keySize != 2048 && keySize != 4096)
            {
                throw new Exception("Please pass in a valid key size.");
            }

            RsaKeyPair keyPair = NativeMethods.get_key_pair((nuint)keySize);
            CasErrorHandler.ThrowIfError(keyPair.error_code, "RSA key pair generation");
            return new RsaKeyPairResult()
            {
                PrivateKey = NativeString.ReadAndFree(keyPair.priv_key),
                PublicKey = NativeString.ReadAndFree(keyPair.pub_key)
            };
        }
    }
}
