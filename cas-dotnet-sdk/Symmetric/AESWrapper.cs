using CasCoreLib;
using CasDotnetSdk.Helpers;
using System;

namespace CasDotnetSdk.Symmetric
{
    public unsafe class AESWrapper 
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
            CasErrorHandler.ThrowIfError(keyResult.error_code, "AES-128 key generation");
            return NativeByteBuffer.CopyAndFree(keyResult.key, keyResult.length);
        }

        /// <summary>
        /// Generates an AES 256 bit key.
        /// </summary>
        public byte[] Aes256Key()
        {
            AesKeyResult keyResult = NativeMethods.aes_256_key();
            CasErrorHandler.ThrowIfError(keyResult.error_code, "AES-256 key generation");
            return NativeByteBuffer.CopyAndFree(keyResult.key, keyResult.length);
        }

        /// <summary>
        /// Derives an AES-256-GCM key from an X25519 shared secret with HKDF-SHA256, bound to the
        /// cipher and to both parties' public keys. Generate the nonce separately with
        /// <see cref="GenerateAESNonce"/>; this method returns only the key.
        /// </summary>
        /// <param name="sharedSecret">The 32-byte shared secret from <c>X25519Wrapper.GenerateSharedSecret</c>.</param>
        /// <param name="publicKeyA">One party's 32-byte X25519 public key.</param>
        /// <param name="publicKeyB">The other party's 32-byte X25519 public key. The two public keys can be passed in either order, so both peers derive the same key.</param>
        /// <exception cref="CasException"><see cref="CasErrorCode.InvalidKey"/> when the shared secret is all zero (a low-order peer public key) or a length is wrong.</exception>
        public byte[] Aes256KeyFromX25519SharedSecret(byte[] sharedSecret, byte[] publicKeyA, byte[] publicKeyB)
        {
            return KeyFromX25519SharedSecret(sharedSecret, publicKeyA, publicKeyB, NativeMethods.aes_256_key_from_x25519_diffie_hellman_shared_secret, "AES-256 key from X25519 shared secret");
        }

        /// <summary>
        /// Derives an AES-128-GCM key from an X25519 shared secret with HKDF-SHA256, bound to the
        /// cipher and to both parties' public keys. Generate the nonce separately with
        /// <see cref="GenerateAESNonce"/>; this method returns only the key.
        /// </summary>
        /// <param name="sharedSecret">The 32-byte shared secret from <c>X25519Wrapper.GenerateSharedSecret</c>.</param>
        /// <param name="publicKeyA">One party's 32-byte X25519 public key.</param>
        /// <param name="publicKeyB">The other party's 32-byte X25519 public key. The two public keys can be passed in either order, so both peers derive the same key.</param>
        /// <exception cref="CasException"><see cref="CasErrorCode.InvalidKey"/> when the shared secret is all zero (a low-order peer public key) or a length is wrong.</exception>
        public byte[] Aes128KeyFromX25519SharedSecret(byte[] sharedSecret, byte[] publicKeyA, byte[] publicKeyB)
        {
            return KeyFromX25519SharedSecret(sharedSecret, publicKeyA, publicKeyB, NativeMethods.aes_128_key_from_x25519_diffie_hellman_shared_secret, "AES-128 key from X25519 shared secret");
        }

        private delegate AesNonceAndKeyFromX25519DiffieHellman X25519KdfFn(byte* sharedSecret, nuint sharedSecretLength, byte* publicKeyA, nuint publicKeyALength, byte* publicKeyB, nuint publicKeyBLength);

        private static byte[] KeyFromX25519SharedSecret(byte[] sharedSecret, byte[] publicKeyA, byte[] publicKeyB, X25519KdfFn nativeDerive, string operation)
        {
            if (sharedSecret == null || sharedSecret.Length == 0)
            {
                throw new ArgumentException("You must provide an X25519 shared secret to derive an AES key.", nameof(sharedSecret));
            }
            if (publicKeyA == null || publicKeyA.Length == 0)
            {
                throw new ArgumentException("You must provide both X25519 public keys to derive an AES key.", nameof(publicKeyA));
            }
            if (publicKeyB == null || publicKeyB.Length == 0)
            {
                throw new ArgumentException("You must provide both X25519 public keys to derive an AES key.", nameof(publicKeyB));
            }

            fixed (byte* secretPtr = sharedSecret)
            fixed (byte* publicKeyAPtr = publicKeyA)
            fixed (byte* publicKeyBPtr = publicKeyB)
            {
                AesNonceAndKeyFromX25519DiffieHellman result = nativeDerive(secretPtr, (nuint)sharedSecret.Length, publicKeyAPtr, (nuint)publicKeyA.Length, publicKeyBPtr, (nuint)publicKeyB.Length);
                CasErrorHandler.ThrowIfError(result.error_code, operation);
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
            CasErrorHandler.ThrowIfError(nonceResult.error_code, "AES nonce generation");
            return NativeByteBuffer.CopyAndFree(nonceResult.nonce, nonceResult.length);
        }
    }
}
