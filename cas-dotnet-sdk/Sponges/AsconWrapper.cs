using CasCoreLib;
using CasDotnetSdk.Helpers;
using System;

namespace CasDotnetSdk.Sponges
{
    public unsafe class AsconWrapper 
    {
        public AsconWrapper()
        {
        }

        /// <summary>
        /// Generates a key for Ascon 128
        /// </summary>
        public byte[] Ascon128Key()
        {
            CasCoreLib.Ascon128Key keyResult = NativeMethods.ascon_128_key();
            CasErrorHandler.ThrowIfError(keyResult.error_code, "Ascon-128 key generation");
            return NativeByteBuffer.CopyAndFree(keyResult.key, keyResult.length);
        }

        /// <summary>
        /// Generates a nonce for Ascon 128
        /// </summary>
        public byte[] Ascon128Nonce()
        {
            CasCoreLib.Ascon128Nonce nonceResult = NativeMethods.ascon_128_nonce();
            CasErrorHandler.ThrowIfError(nonceResult.error_code, "Ascon-128 nonce generation");
            return NativeByteBuffer.CopyAndFree(nonceResult.nonce, nonceResult.length);
        }

        /// <summary>
        /// Encrypts with Ascon-AEAD128 under a caller-supplied 16-byte nonce and returns
        /// <c>ciphertext || tag</c>. Never reuse a nonce under the same key. Prefer
        /// <see cref="Ascon128Seal"/>, which manages the nonce.
        /// </summary>
        public byte[] Ascon128Encrypt(byte[] nonce, byte[] key, byte[] toEncrypt)
        {
            if (nonce == null || nonce.Length == 0)
            {
                throw new Exception("You must provide a nonce to encrypt with Ascon 128");
            }
            if (key == null || key.Length == 0)
            {
                throw new Exception("You must provide a key to encrypt with Ascon 128");
            }
            if (toEncrypt == null || toEncrypt.Length == 0)
            {
                throw new Exception("You must provide data to encrypt with Ascon 128");
            }

            fixed (byte* noncePtr = NativePin.Of(nonce))
            fixed (byte* keyPtr = NativePin.Of(key))
            fixed (byte* dataPtr = NativePin.Of(toEncrypt))
            {
                Ascon128EncryptResult encryptResult = NativeMethods.ascon_128_encrypt(noncePtr, (nuint)nonce.Length, keyPtr, (nuint)key.Length, dataPtr, (nuint)toEncrypt.Length);
                CasErrorHandler.ThrowIfError(encryptResult.error_code, "Ascon-128 encrypt");
                return NativeByteBuffer.CopyAndFree(encryptResult.ciphertext, encryptResult.length);
            }
        }

        /// <summary>
        /// Decrypts Ascon-AEAD128 <c>ciphertext || tag</c> from <see cref="Ascon128Encrypt(byte[], byte[], byte[])"/>.
        /// </summary>
        public byte[] Ascon128Decrypt(byte[] nonce, byte[] key, byte[] toDecrypt)
        {
            if (nonce == null || nonce.Length == 0)
            {
                throw new Exception("You must provide a nonce to decrypt with Ascon 128");
            }
            if (key == null || key.Length == 0)
            {
                throw new Exception("You must provide a key to decrypt with Ascon 128");
            }
            if (toDecrypt == null || toDecrypt.Length == 0)
            {
                throw new Exception("You must provide data to decrypt with Ascon 128");
            }

            fixed (byte* noncePtr = NativePin.Of(nonce))
            fixed (byte* keyPtr = NativePin.Of(key))
            fixed (byte* dataPtr = NativePin.Of(toDecrypt))
            {
                Ascon128DecryptResult decryptResult = NativeMethods.ascon_128_decrypt(noncePtr, (nuint)nonce.Length, keyPtr, (nuint)key.Length, dataPtr, (nuint)toDecrypt.Length);
                CasErrorHandler.ThrowIfError(decryptResult.error_code, "Ascon-128 decrypt");
                return NativeByteBuffer.CopyAndFree(decryptResult.plaintext, decryptResult.length);
            }
        }

        /// <summary>
        /// Encrypts with Ascon-AEAD128 under a fresh random 128-bit nonce and returns
        /// <c>nonce (16 bytes) || ciphertext || tag (16 bytes)</c>. This is the recommended way to
        /// encrypt: the caller never handles a nonce, so it cannot reuse one.
        /// </summary>
        /// <param name="key">A 16-byte key from <see cref="Ascon128Key"/>.</param>
        /// <param name="plaintext">The data to encrypt. May be empty.</param>
        /// <param name="aad">Associated data: authenticated, not encrypted, and not included in the result. It must match on <see cref="Ascon128Open"/>. <c>null</c> means empty.</param>
        /// <exception cref="CasException"><see cref="CasErrorCode.InvalidKey"/> when the key is not 16 bytes.</exception>
        public byte[] Ascon128Seal(byte[] key, byte[] plaintext, byte[]? aad = null)
        {
            ArgumentNullException.ThrowIfNull(key);
            ArgumentNullException.ThrowIfNull(plaintext);

            fixed (byte* keyPtr = NativePin.Of(key))
            fixed (byte* plaintextPtr = NativePin.Of(plaintext))
            fixed (byte* aadPtr = aad)
            {
                // A null pointer with length 0 is an empty AAD.
                Ascon128EncryptResult result = NativeMethods.ascon_128_seal(keyPtr, (nuint)key.Length, plaintextPtr, (nuint)plaintext.Length, aadPtr, (nuint)(aad?.Length ?? 0));
                CasErrorHandler.ThrowIfError(result.error_code, "Ascon-128 seal");
                return NativeByteBuffer.CopyAndFree(result.ciphertext, result.length);
            }
        }

        /// <summary>
        /// Decrypts a <c>nonce || ciphertext || tag</c> message produced by <see cref="Ascon128Seal"/>.
        /// </summary>
        /// <param name="key">The 16-byte key the message was sealed with.</param>
        /// <param name="sealedMessage">The output of <see cref="Ascon128Seal"/>.</param>
        /// <param name="aad">The same associated data passed to <see cref="Ascon128Seal"/>. <c>null</c> means empty.</param>
        /// <exception cref="CasException"><see cref="CasErrorCode.DecryptionFailed"/> when the message was tampered with or the key or AAD is wrong; <see cref="CasErrorCode.InvalidInput"/> when it is shorter than a nonce plus a tag.</exception>
        public byte[] Ascon128Open(byte[] key, byte[] sealedMessage, byte[]? aad = null)
        {
            ArgumentNullException.ThrowIfNull(key);
            ArgumentNullException.ThrowIfNull(sealedMessage);

            fixed (byte* keyPtr = NativePin.Of(key))
            fixed (byte* sealedPtr = NativePin.Of(sealedMessage))
            fixed (byte* aadPtr = aad)
            {
                Ascon128DecryptResult result = NativeMethods.ascon_128_open(keyPtr, (nuint)key.Length, sealedPtr, (nuint)sealedMessage.Length, aadPtr, (nuint)(aad?.Length ?? 0));
                CasErrorHandler.ThrowIfError(result.error_code, "Ascon-128 open");
                return NativeByteBuffer.CopyAndFree(result.plaintext, result.length);
            }
        }

        /// <summary>
        /// Encrypts with Ascon-AEAD128 and associated data under a caller-supplied 16-byte nonce,
        /// and returns <c>ciphertext || tag</c>. Never reuse a nonce under the same key. Prefer
        /// <see cref="Ascon128Seal"/>, which manages the nonce and also takes associated data.
        /// </summary>
        /// <param name="nonce">A 16-byte nonce from <see cref="Ascon128Nonce"/>, used for this message only.</param>
        /// <param name="key">A 16-byte key from <see cref="Ascon128Key"/>.</param>
        /// <param name="toEncrypt">The data to encrypt. May be empty.</param>
        /// <param name="aad">Associated data: authenticated, not encrypted, and not included in the result. It must match on <see cref="Ascon128Decrypt(byte[], byte[], byte[], byte[])"/>. <c>null</c> means empty.</param>
        public byte[] Ascon128Encrypt(byte[] nonce, byte[] key, byte[] toEncrypt, byte[]? aad)
        {
            ArgumentNullException.ThrowIfNull(nonce);
            ArgumentNullException.ThrowIfNull(key);
            ArgumentNullException.ThrowIfNull(toEncrypt);

            fixed (byte* noncePtr = NativePin.Of(nonce))
            fixed (byte* keyPtr = NativePin.Of(key))
            fixed (byte* dataPtr = NativePin.Of(toEncrypt))
            fixed (byte* aadPtr = aad)
            {
                Ascon128EncryptResult result = NativeMethods.ascon_128_encrypt_with_aad(noncePtr, (nuint)nonce.Length, keyPtr, (nuint)key.Length, dataPtr, (nuint)toEncrypt.Length, aadPtr, (nuint)(aad?.Length ?? 0));
                CasErrorHandler.ThrowIfError(result.error_code, "Ascon-128 encrypt with AAD");
                return NativeByteBuffer.CopyAndFree(result.ciphertext, result.length);
            }
        }

        /// <summary>
        /// Decrypts Ascon-AEAD128 <c>ciphertext || tag</c> produced with associated data.
        /// </summary>
        /// <param name="nonce">The nonce the data was encrypted with.</param>
        /// <param name="key">The 16-byte key the data was encrypted with.</param>
        /// <param name="toDecrypt">The <c>ciphertext || tag</c> to decrypt.</param>
        /// <param name="aad">The same associated data passed on encryption. <c>null</c> means empty.</param>
        /// <exception cref="CasException"><see cref="CasErrorCode.DecryptionFailed"/> when the ciphertext was tampered with or the key, nonce or AAD is wrong.</exception>
        public byte[] Ascon128Decrypt(byte[] nonce, byte[] key, byte[] toDecrypt, byte[]? aad)
        {
            ArgumentNullException.ThrowIfNull(nonce);
            ArgumentNullException.ThrowIfNull(key);
            ArgumentNullException.ThrowIfNull(toDecrypt);

            fixed (byte* noncePtr = NativePin.Of(nonce))
            fixed (byte* keyPtr = NativePin.Of(key))
            fixed (byte* dataPtr = NativePin.Of(toDecrypt))
            fixed (byte* aadPtr = aad)
            {
                Ascon128DecryptResult result = NativeMethods.ascon_128_decrypt_with_aad(noncePtr, (nuint)nonce.Length, keyPtr, (nuint)key.Length, dataPtr, (nuint)toDecrypt.Length, aadPtr, (nuint)(aad?.Length ?? 0));
                CasErrorHandler.ThrowIfError(result.error_code, "Ascon-128 decrypt with AAD");
                return NativeByteBuffer.CopyAndFree(result.plaintext, result.length);
            }
        }
    }
}
