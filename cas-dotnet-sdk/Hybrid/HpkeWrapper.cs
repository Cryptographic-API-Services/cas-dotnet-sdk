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
            return new HpkeKeyPairResult()
            {
                PrivateKey = NativeByteBuffer.CopyAndFree(keyPair.private_key_ptr, keyPair.private_key_ptr_length),
                PublicKey = NativeByteBuffer.CopyAndFree(keyPair.public_key_ptr, keyPair.public_key_ptr_length),
                InfoStr = NativeByteBuffer.CopyAndFree(keyPair.info_str_ptr, keyPair.info_str_ptr_length)
            };
        }

        public HpkeEncryptResult Encrypt(byte[] plaintText, byte[] publicKey, byte[] infoStr)
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
            {
                HpkeEncrypt encrypt = NativeMethods.hpke_encrypt(plaintextPtr, (nuint)plaintText.Length, publicKeyPtr, (nuint)publicKey.Length, infoStrPtr, (nuint)infoStr.Length);
                CasErrorHandler.ThrowIfError(encrypt.error_code, "HPKE encrypt");
                return new HpkeEncryptResult()
                {
                    EncappedKey = NativeByteBuffer.CopyAndFree(encrypt.encapped_key_ptr, encrypt.encapped_key_ptr_length),
                    Ciphertext = NativeByteBuffer.CopyAndFree(encrypt.ciphertext_ptr, encrypt.ciphertext_ptr_length),
                    Tag = NativeByteBuffer.CopyAndFree(encrypt.tag_ptr, encrypt.tag_ptr_length)
                };
            }
        }

        public byte[] Decrypt(byte[] cipherText, byte[] privateKey, byte[] encappedKey, byte[] tag, byte[] infoStr)
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
            {
                HpkeDecrypt decrypt = NativeMethods.hpke_decrypt(cipherTextPtr, (nuint)cipherText.Length, privateKeyPtr, (nuint)privateKey.Length, encappedKeyPtr, (nuint)encappedKey.Length, tagPtr, (nuint)tag.Length, infoStrPtr, (nuint)infoStr.Length);
                CasErrorHandler.ThrowIfError(decrypt.error_code, "HPKE decrypt");
                return NativeByteBuffer.CopyAndFree(decrypt.plaintext_ptr, decrypt.plaintext_ptr_length);
            }
        }
    }
}
