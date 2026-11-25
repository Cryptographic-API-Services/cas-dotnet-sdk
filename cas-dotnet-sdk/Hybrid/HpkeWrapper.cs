using CasCoreLib;
using CasDotnetSdk.Helpers;
using CasDotnetSdk.Hybrid.Types;
using System;

namespace CasDotnetSdk.Hybrid
{
    public unsafe class HpkeWrapper 
    {
        public HpkeWrapper()
        {
        }

        /// <summary>
        /// Generates a Private Key, Public Key, and InfoStr for usage with HPKE
        /// </summary>
        public HpkeKeyPairResult GenerateKeyPair()
        {
            HpkeKeyPair keyPair = NativeMethods.hpke_generate_keypair();
            try
            {
                CasErrorHandler.ThrowIfError(keyPair.error_code, "HPKE key generation");
                return new HpkeKeyPairResult()
                {
                    PrivateKey = NativeByteBuffer.Copy(keyPair.private_key_ptr, keyPair.private_key_ptr_length),
                    PublicKey = NativeByteBuffer.Copy(keyPair.public_key_ptr, keyPair.public_key_ptr_length),
                    InfoStr = NativeByteBuffer.Copy(keyPair.info_str_ptr, keyPair.info_str_ptr_length)
                };
            }
            finally
            {
                NativeMethods.free_hpke_key_pair(&keyPair);
            }
        }

        /// <summary>
        /// Encrypts with HPKE (RFC 9180) base mode: X25519, HKDF-SHA512, AES-256-GCM.
        /// </summary>
        /// <param name="plaintText">The message to encrypt.</param>
        /// <param name="publicKey">The recipient's public key.</param>
        /// <param name="infoStr">Application context that both sides agree on (RFC 9180 <c>info</c>), at most 65,530 bytes.</param>
        /// <param name="aad">Optional associated data: authenticated, not encrypted, and not included in the result. The recipient must pass the same bytes to <see cref="Decrypt"/>. <c>null</c> means empty.</param>
        public HpkeEncryptResult Encrypt(byte[] plaintText, byte[] publicKey, byte[] infoStr, byte[]? aad = null)
        {
            if (plaintText == null || plaintText.Length == 0)
            {
                throw new Exception("Must provide plaint text to encrypt with HPKE");
            }
            if (publicKey == null || publicKey.Length == 0)
            {
                throw new Exception("Must a public key to encrypt with HPKE");
            }
            if (infoStr == null || infoStr.Length == 0)
            {
                throw new Exception("Must a info str to encrypt with HPKE");
            }

            fixed (byte* plaintextPtr = NativePin.Of(plaintText))
            fixed (byte* publicKeyPtr = NativePin.Of(publicKey))
            fixed (byte* infoStrPtr = NativePin.Of(infoStr))
            fixed (byte* aadPtr = aad)
            {
                // A null pointer with length 0 is an empty AAD.
                HpkeEncrypt encrypt = NativeMethods.hpke_encrypt(plaintextPtr, (nuint)plaintText.Length, publicKeyPtr, (nuint)publicKey.Length, infoStrPtr, (nuint)infoStr.Length, aadPtr, (nuint)(aad?.Length ?? 0));
                try
                {
                    CasErrorHandler.ThrowIfError(encrypt.error_code, "HPKE encrypt");
                    return new HpkeEncryptResult()
                    {
                        EncappedKey = NativeByteBuffer.Copy(encrypt.encapped_key_ptr, encrypt.encapped_key_ptr_length),
                        Ciphertext = NativeByteBuffer.Copy(encrypt.ciphertext_ptr, encrypt.ciphertext_ptr_length),
                        Tag = NativeByteBuffer.Copy(encrypt.tag_ptr, encrypt.tag_ptr_length)
                    };
                }
                finally
                {
                    NativeMethods.free_hpke_encrypt(&encrypt);
                }
            }
        }

        /// <summary>
        /// Decrypts an HPKE (RFC 9180) base-mode message produced by <see cref="Encrypt"/>.
        /// </summary>
        /// <param name="cipherText">The ciphertext.</param>
        /// <param name="privateKey">The recipient's private key.</param>
        /// <param name="encappedKey">The encapsulated key from the sender.</param>
        /// <param name="tag">The authentication tag from the sender.</param>
        /// <param name="infoStr">The same application context the sender used.</param>
        /// <param name="aad">The same associated data the sender used. <c>null</c> means empty.</param>
        public byte[] Decrypt(byte[] cipherText, byte[] privateKey, byte[] encappedKey, byte[] tag, byte[] infoStr, byte[]? aad = null)
        {
            if (cipherText == null || cipherText.Length == 0)
            {
                throw new Exception("Must provide ciphertext to decrypt with HPKE");
            }
            if (privateKey == null || privateKey.Length == 0)
            {
                throw new Exception("Must a private key to decrypt with HPKE");
            }
            if (encappedKey == null || encappedKey.Length == 0)
            {
                throw new Exception("Must provide an encapped key to decrypt with HPKE");
            }
            if (tag == null || tag.Length == 0)
            {
                throw new Exception("Must provide a tag to decrypt with HPKE");
            }
            if (infoStr == null || infoStr.Length == 0)
            {
                throw new Exception("Must a info str to decrypt with HPKE");
            }

            fixed (byte* cipherTextPtr = NativePin.Of(cipherText))
            fixed (byte* privateKeyPtr = NativePin.Of(privateKey))
            fixed (byte* encappedKeyPtr = NativePin.Of(encappedKey))
            fixed (byte* tagPtr = NativePin.Of(tag))
            fixed (byte* infoStrPtr = NativePin.Of(infoStr))
            fixed (byte* aadPtr = aad)
            {
                HpkeDecrypt decrypt = NativeMethods.hpke_decrypt(cipherTextPtr, (nuint)cipherText.Length, privateKeyPtr, (nuint)privateKey.Length, encappedKeyPtr, (nuint)encappedKey.Length, tagPtr, (nuint)tag.Length, infoStrPtr, (nuint)infoStr.Length, aadPtr, (nuint)(aad?.Length ?? 0));
                CasErrorHandler.ThrowIfError(decrypt.error_code, "HPKE decrypt");
                return NativeByteBuffer.CopyAndFree(decrypt.plaintext_ptr, decrypt.plaintext_ptr_length);
            }
        }
    }
}
