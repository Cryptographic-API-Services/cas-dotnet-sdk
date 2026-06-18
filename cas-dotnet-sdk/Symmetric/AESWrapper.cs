using CasCoreLib;
using CasDotnetSdk.Helpers;
using System;

namespace CasDotnetSdk.Symmetric
{
    public unsafe class AESWrapper : BaseWrapper
    {
        /// <summary>
        /// A wrapper class for AES-GCM 128 and 256 bit encryption and decryption.
        /// </summary>
        public AESWrapper()
        {
        }

        /// <summary>
        /// Generates an AES 128 bit key.
        /// </summary>
        public byte[] Aes128Key()
        {
            AesKeyResult keyResult = NativeMethods.aes_128_key();
            return NativeByteBuffer.CopyAndFree(keyResult.key, keyResult.length);
        }

        /// <summary>
        /// Generates an AES 256 bit key.
        /// </summary>
        public byte[] Aes256Key()
        {
            AesKeyResult keyResult = NativeMethods.aes_256_key();
            return NativeByteBuffer.CopyAndFree(keyResult.key, keyResult.length);
        }

        /// <summary>
        /// Generates an AES 256 bit key and nonce based off a X25519 Diffie Hellman shared secret.
        /// </summary>
        public byte[] Aes256KeyNonceX25519DiffieHellman(byte[] sharedSecret)
        {
            if (sharedSecret == null || sharedSecret.Length == 0)
            {
                throw new Exception("You must provide allocated data for X25519 shared secret to generate an AES Key");
            }

            fixed (byte* secretPtr = NativePin.Of(sharedSecret))
            {
                AesNonceAndKeyFromX25519DiffieHellman result = NativeMethods.aes_256_key_from_x25519_diffie_hellman_shared_secret(secretPtr, (nuint)sharedSecret.Length);
                CasErrorHandler.ThrowIfError(result.error_code, "AES-256 key from X25519 shared secret");
                return NativeByteBuffer.CopyAndFree(result.aes_key_ptr, result.aes_key_ptr_length);
            }
        }

        /// <summary>
        /// Generates an AES 128 bit key and nonce based off a X25519 Diffie Hellman shared secret.
        /// </summary>
        public byte[] Aes128KeyNonceX25519DiffieHellman(byte[] sharedSecret)
        {
            if (sharedSecret == null || sharedSecret.Length == 0)
            {
                throw new Exception("You must provide allocated data for X25519 shared secret to generate an AES Key");
            }

            fixed (byte* secretPtr = NativePin.Of(sharedSecret))
            {
                AesNonceAndKeyFromX25519DiffieHellman result = NativeMethods.aes_128_key_from_x25519_diffie_hellman_shared_secret(secretPtr, (nuint)sharedSecret.Length);
                CasErrorHandler.ThrowIfError(result.error_code, "AES-128 key from X25519 shared secret");
                return NativeByteBuffer.CopyAndFree(result.aes_key_ptr, result.aes_key_ptr_length);
            }
        }

        /// <summary>
        /// Encrypts with AES-256-GCM.
        /// </summary>
        public byte[] Aes256Encrypt(byte[] nonceKey, byte[] key, byte[] toEncrypt)
        {
            fixed (byte* noncePtr = NativePin.Of(nonceKey))
            fixed (byte* keyPtr = NativePin.Of(key))
            fixed (byte* dataPtr = NativePin.Of(toEncrypt))
            {
                AesBytesEncrypt encryptResult = NativeMethods.aes_256_encrypt_bytes_with_key(noncePtr, (nuint)nonceKey.Length, keyPtr, (nuint)key.Length, dataPtr, (nuint)toEncrypt.Length);
                CasErrorHandler.ThrowIfError(encryptResult.error_code, "AES-256 encrypt");
                return NativeByteBuffer.CopyAndFree(encryptResult.ciphertext, encryptResult.length);
            }
        }

        /// <summary>
        /// Decrypts with AES-256-GCM.
        /// </summary>
        public byte[] Aes256Decrypt(byte[] nonceKey, byte[] key, byte[] toDecrypt)
        {
            fixed (byte* noncePtr = NativePin.Of(nonceKey))
            fixed (byte* keyPtr = NativePin.Of(key))
            fixed (byte* dataPtr = NativePin.Of(toDecrypt))
            {
                AesBytesDecrypt decryptResult = NativeMethods.aes_256_decrypt_bytes_with_key(noncePtr, (nuint)nonceKey.Length, keyPtr, (nuint)key.Length, dataPtr, (nuint)toDecrypt.Length);
                CasErrorHandler.ThrowIfError(decryptResult.error_code, "AES-256 decrypt");
                return NativeByteBuffer.CopyAndFree(decryptResult.plaintext, decryptResult.length);
            }
        }

        /// <summary>
        /// Encrypts with AES-128-GCM.
        /// </summary>
        public byte[] Aes128Encrypt(byte[] nonceKey, byte[] key, byte[] dataToEncrypt)
        {
            fixed (byte* noncePtr = NativePin.Of(nonceKey))
            fixed (byte* keyPtr = NativePin.Of(key))
            fixed (byte* dataPtr = NativePin.Of(dataToEncrypt))
            {
                AesBytesEncrypt encryptResult = NativeMethods.aes_128_encrypt_bytes_with_key(noncePtr, (nuint)nonceKey.Length, keyPtr, (nuint)key.Length, dataPtr, (nuint)dataToEncrypt.Length);
                CasErrorHandler.ThrowIfError(encryptResult.error_code, "AES-128 encrypt");
                return NativeByteBuffer.CopyAndFree(encryptResult.ciphertext, encryptResult.length);
            }
        }

        /// <summary>
        /// Decrypts with AES-128-GCM.
        /// </summary>
        public byte[] Aes128Decrypt(byte[] nonceKey, byte[] key, byte[] dataToDecrypt)
        {
            fixed (byte* noncePtr = NativePin.Of(nonceKey))
            fixed (byte* keyPtr = NativePin.Of(key))
            fixed (byte* dataPtr = NativePin.Of(dataToDecrypt))
            {
                AesBytesDecrypt decryptResult = NativeMethods.aes_128_decrypt_bytes_with_key(noncePtr, (nuint)nonceKey.Length, keyPtr, (nuint)key.Length, dataPtr, (nuint)dataToDecrypt.Length);
                CasErrorHandler.ThrowIfError(decryptResult.error_code, "AES-128 decrypt");
                return NativeByteBuffer.CopyAndFree(decryptResult.plaintext, decryptResult.length);
            }
        }

        /// <summary>
        /// Generates a AES Nonce usuable for AES-128-GCM and AES-256-GCM.
        /// </summary>
        public byte[] GenerateAESNonce()
        {
            AesNonce nonceResult = NativeMethods.aes_nonce();
            return NativeByteBuffer.CopyAndFree(nonceResult.nonce, nonceResult.length);
        }
    }
}
