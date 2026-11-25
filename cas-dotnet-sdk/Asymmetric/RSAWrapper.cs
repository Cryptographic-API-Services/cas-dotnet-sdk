using CasCoreLib;
using CasDotnetSdk.Asymmetric.Types;
using CasDotnetSdk.Helpers;
using System;

namespace CasDotnetSdk.Asymmetric
{
    public unsafe class RSAWrapper 
    {
        /// <summary>
        /// A wrapper class for RSA key generation, signing, and verification.
        /// </summary>
        public RSAWrapper()
        {
        }

        /// <summary>
        /// Signs data with an RSA private key using RSASSA-PKCS1-v1_5 with SHA-256 (RS256).
        /// The message is hashed inside the library, so pass the message itself, not a digest.
        /// The signature verifies with any standard RS256 verifier (for example .NET's
        /// <c>RSA.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)</c>).
        /// </summary>
        /// <param name="privateKey">The PKCS#8 PEM private key from <see cref="GetKeyPair"/>.</param>
        /// <param name="dataToSign">The message to sign.</param>
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
        /// Verifies an RS256 (RSASSA-PKCS1-v1_5 with SHA-256) signature made by <see cref="Sign"/>.
        /// </summary>
        /// <param name="publicKey">The PEM public key from <see cref="GetKeyPair"/>.</param>
        /// <param name="dataToVerify">The message that was signed.</param>
        /// <param name="signature">The signature to check.</param>
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
        /// Generates an RSA key pair as PEM strings.
        /// </summary>
        /// <param name="keySize">The modulus size in bits: 2048, 3072, or 4096.</param>
        /// <exception cref="ArgumentOutOfRangeException">The key size is not 2048, 3072, or 4096.</exception>
        public RsaKeyPairResult GetKeyPair(int keySize)
        {
            if (keySize != 2048 && keySize != 3072 && keySize != 4096)
            {
                throw new ArgumentOutOfRangeException(nameof(keySize), keySize, "RSA key size must be 2048, 3072, or 4096 bits.");
            }

            RsaKeyPair keyPair = NativeMethods.get_key_pair((nuint)keySize);
            try
            {
                CasErrorHandler.ThrowIfError(keyPair.error_code, "RSA key pair generation");
                return new RsaKeyPairResult()
                {
                    PrivateKey = NativeString.Read(keyPair.priv_key),
                    PublicKey = NativeString.Read(keyPair.pub_key)
                };
            }
            finally
            {
                NativeMethods.free_rsa_key_pair(&keyPair);
            }
        }
    }
}
