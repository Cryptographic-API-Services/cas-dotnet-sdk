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
        /// Use it to interoperate with RS256; for new code, prefer <see cref="SignPss"/>.
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
        /// Signs data with an RSA private key using RSASSA-PSS with SHA-256, MGF1-SHA-256 and a
        /// 32-byte random salt (PS256). Recommended over <see cref="Sign"/> for new code.
        /// The message is hashed inside the library, so pass the message itself, not a digest.
        /// PSS signatures are randomized: signing the same message twice gives different
        /// signatures, and both verify. The signature verifies with any standard PS256 verifier
        /// (for example .NET's <c>RSA.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss)</c>).
        /// </summary>
        /// <param name="privateKey">The PKCS#8 PEM private key from <see cref="GetKeyPair"/>.</param>
        /// <param name="dataToSign">The message to sign.</param>
        /// <exception cref="ArgumentNullException"><paramref name="privateKey"/> or <paramref name="dataToSign"/> is null.</exception>
        /// <exception cref="ArgumentException"><paramref name="dataToSign"/> is empty.</exception>
        /// <exception cref="CasException">The key is not a valid PKCS#8 PEM key of at least 2048 bits, or signing failed.</exception>
        public byte[] SignPss(string privateKey, byte[] dataToSign)
        {
            if (privateKey == null)
            {
                throw new ArgumentNullException(nameof(privateKey));
            }
            if (dataToSign == null)
            {
                throw new ArgumentNullException(nameof(dataToSign));
            }
            if (dataToSign.Length == 0)
            {
                throw new ArgumentException("You must provide allocated data to sign with RSA-PSS.", nameof(dataToSign));
            }

            fixed (byte* privateKeyPtr = NativeString.ToCString(privateKey))
            fixed (byte* dataPtr = NativePin.Of(dataToSign))
            {
                RsaSignBytesResults signResult = NativeMethods.rsa_sign_pss_with_key_bytes(privateKeyPtr, dataPtr, (nuint)dataToSign.Length);
                CasErrorHandler.ThrowIfError(signResult.error_code, "RSA-PSS sign");
                return NativeByteBuffer.CopyAndFree(signResult.signature_raw_ptr, signResult.length);
            }
        }

        /// <summary>
        /// Verifies an RSASSA-PSS SHA-256 (PS256) signature made by <see cref="SignPss"/> or any
        /// standard PS256 signer. The signature must use MGF1-SHA-256 and a 32-byte salt; other
        /// salt lengths don't verify.
        /// </summary>
        /// <param name="publicKey">The PKCS#1 PEM public key from <see cref="GetKeyPair"/>.</param>
        /// <param name="dataToVerify">The message that was signed.</param>
        /// <param name="signature">The signature to check.</param>
        /// <returns><c>true</c> if the signature is valid for the message and key; otherwise <c>false</c>.</returns>
        /// <exception cref="ArgumentNullException">An argument is null.</exception>
        /// <exception cref="ArgumentException"><paramref name="dataToVerify"/> or <paramref name="signature"/> is empty.</exception>
        /// <exception cref="CasException">The key is not a valid PKCS#1 PEM key of at least 2048 bits.</exception>
        public bool VerifyPss(string publicKey, byte[] dataToVerify, byte[] signature)
        {
            if (publicKey == null)
            {
                throw new ArgumentNullException(nameof(publicKey));
            }
            if (dataToVerify == null)
            {
                throw new ArgumentNullException(nameof(dataToVerify));
            }
            if (signature == null)
            {
                throw new ArgumentNullException(nameof(signature));
            }
            if (dataToVerify.Length == 0)
            {
                throw new ArgumentException("You must provide allocated data to verify with RSA-PSS.", nameof(dataToVerify));
            }
            if (signature.Length == 0)
            {
                throw new ArgumentException("You must provide an allocated signature to verify with RSA-PSS.", nameof(signature));
            }

            fixed (byte* publicKeyPtr = NativeString.ToCString(publicKey))
            fixed (byte* dataPtr = NativePin.Of(dataToVerify))
            fixed (byte* signaturePtr = NativePin.Of(signature))
            {
                CasVerifyResult result = NativeMethods.rsa_verify_pss_bytes(publicKeyPtr, dataPtr, (nuint)dataToVerify.Length, signaturePtr, (nuint)signature.Length);
                CasErrorHandler.ThrowIfError(result.error_code, "RSA-PSS verify");
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
