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
            return NativeByteBuffer.CopyAndFree(keyResult.key, keyResult.length);
        }

        /// <summary>
        /// Generates a nonce for Ascon 128
        /// </summary>
        public byte[] Ascon128Nonce()
        {
            CasCoreLib.Ascon128Nonce nonceResult = NativeMethods.ascon_128_nonce();
            return NativeByteBuffer.CopyAndFree(nonceResult.nonce, nonceResult.length);
        }

        /// <summary>
        /// Encrypts with Ascond 128
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
        /// Decrypts with Ascond 128
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
    }
}
