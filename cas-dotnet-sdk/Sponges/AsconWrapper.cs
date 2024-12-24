using CasDotnetSdk.Helpers;
using CasDotnetSdk.Sponges.Linux;
using CasDotnetSdk.Sponges.Types;
using CasDotnetSdk.Sponges.Windows;
using System;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Sponges
{
    public class AsconWrapper : BaseWrapper
    {
        public AsconWrapper()
        {
        }

        /// <summary>
        /// Generates a key for Ascon 128
        /// </summary>
        /// <returns></returns>
        public byte[] Ascon128Key()
        {
            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                Ascon128KeyStruct keyPtr = AsconLinuxWrapper.ascon_128_key();
                byte[] key = new byte[keyPtr.length];
                Marshal.Copy(keyPtr.key, key, 0, keyPtr.length);
                FreeMemoryHelper.FreeBytesMemory(keyPtr.key);
                DateTime end = DateTime.UtcNow;
                return key;
            }
            else
            {
                Ascon128KeyStruct keyPtr = AsconWindowsWrapper.ascon_128_key();
                byte[] key = new byte[keyPtr.length];
                Marshal.Copy(keyPtr.key, key, 0, keyPtr.length);
                FreeMemoryHelper.FreeBytesMemory(keyPtr.key);
                DateTime end = DateTime.UtcNow;
                return key;
            }
        }

        /// <summary>
        /// Generates a key for Ascon 128 on the threadpool
        /// </summary>
        /// <returns></returns>
        public byte[] Ascon128KeyThreadpool()
        {
            if (!CASConfiguration.IsThreadingEnabled)
            {
                throw new Exception("You do not have the product subscription to work with the thread pool featues");
            }

            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                Ascon128KeyStruct keyPtr = AsconLinuxWrapper.ascon_128_key_threadpool();
                byte[] key = new byte[keyPtr.length];
                Marshal.Copy(keyPtr.key, key, 0, keyPtr.length);
                FreeMemoryHelper.FreeBytesMemory(keyPtr.key);
                DateTime end = DateTime.UtcNow;
                return key;
            }
            else
            {
                Ascon128KeyStruct keyPtr = AsconWindowsWrapper.ascon_128_key_threadpool();
                byte[] key = new byte[keyPtr.length];
                Marshal.Copy(keyPtr.key, key, 0, keyPtr.length);
                FreeMemoryHelper.FreeBytesMemory(keyPtr.key);
                DateTime end = DateTime.UtcNow;
                return key;
            }
        }

        /// <summary>
        /// Generates a nonce for Ascon 128
        /// </summary>
        /// <returns></returns>
        public byte[] Ascon128Nonce()
        {
            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                Ascon128NonceStruct noncePtr = AsconLinuxWrapper.ascon_128_nonce();
                byte[] nonce = new byte[noncePtr.length];
                Marshal.Copy(noncePtr.nonce, nonce, 0, noncePtr.length);
                FreeMemoryHelper.FreeBytesMemory(noncePtr.nonce);
                DateTime end = DateTime.UtcNow;
                return nonce;
            }
            else
            {
                Ascon128NonceStruct noncePtr = AsconWindowsWrapper.ascon_128_nonce();
                byte[] nonce = new byte[noncePtr.length];
                Marshal.Copy(noncePtr.nonce, nonce, 0, noncePtr.length);
                FreeMemoryHelper.FreeBytesMemory(noncePtr.nonce);
                DateTime end = DateTime.UtcNow;
                return nonce;
            }
        }

        /// <summary>
        /// Generates a nonce for Ascon 128 on the threadpool
        /// </summary>
        /// <returns></returns>
        public byte[] Ascon128NonceThreadpool()
        {
            if (!CASConfiguration.IsThreadingEnabled)
            {
                throw new Exception("You do not have the product subscription to work with the thread pool featues");
            }

            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                Ascon128NonceStruct noncePtr = AsconLinuxWrapper.ascon_128_nonce_threadpool();
                byte[] nonce = new byte[noncePtr.length];
                Marshal.Copy(noncePtr.nonce, nonce, 0, noncePtr.length);
                FreeMemoryHelper.FreeBytesMemory(noncePtr.nonce);
                DateTime end = DateTime.UtcNow;
                return nonce;
            }
            else
            {
                Ascon128NonceStruct noncePtr = AsconWindowsWrapper.ascon_128_nonce_threadpool();
                byte[] nonce = new byte[noncePtr.length];
                Marshal.Copy(noncePtr.nonce, nonce, 0, noncePtr.length);
                FreeMemoryHelper.FreeBytesMemory(noncePtr.nonce);
                DateTime end = DateTime.UtcNow;
                return nonce;
            }
        }

        /// <summary>
        /// Encrypts with Ascond 128
        /// </summary>
        /// <param name="nonce"></param>
        /// <param name="key"></param>
        /// <param name="toEncrypt"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public byte[] Ascon128Encrypt(byte[] nonce, byte[] key, byte[] toEncrypt)
        {
            if (nonce?.Length == 0)
            {
                throw new Exception("You must provide a nonce to encrypt with Ascon 128");
            }
            if (key?.Length == 0)
            {
                throw new Exception("You must provide a key to encrypt with Ascon 128");
            }
            if (toEncrypt == null || toEncrypt.Length == 0)
            {
                throw new Exception("You must provide data to encrypt with Ascon 128");
            }

            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                Ascon128EncryptResultStruct encryptResult = AsconLinuxWrapper.ascon_128_encrypt(nonce, nonce.Length, key, key.Length, toEncrypt, toEncrypt.Length);
                byte[] result = new byte[encryptResult.length];
                Marshal.Copy(encryptResult.ciphertext, result, 0, encryptResult.length);
                FreeMemoryHelper.FreeBytesMemory(encryptResult.ciphertext);
                DateTime end = DateTime.UtcNow;
                return result;
            }
            else
            {
                Ascon128EncryptResultStruct encryptResult = AsconWindowsWrapper.ascon_128_encrypt(nonce, nonce.Length, key, key.Length, toEncrypt, toEncrypt.Length);
                byte[] result = new byte[encryptResult.length];
                Marshal.Copy(encryptResult.ciphertext, result, 0, encryptResult.length);
                FreeMemoryHelper.FreeBytesMemory(encryptResult.ciphertext);
                DateTime end = DateTime.UtcNow;
                return result;
            }
        }

        /// <summary>
        /// Encrypts with Ascond 128 on the threadpool
        /// </summary>
        /// <param name="nonce"></param>
        /// <param name="key"></param>
        /// <param name="toEncrypt"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public byte[] Ascon128EncryptThreadpool(byte[] nonce, byte[] key, byte[] toEncrypt)
        {
            if (!CASConfiguration.IsThreadingEnabled)
            {
                throw new Exception("You do not have the product subscription to work with the thread pool featues");
            }

            if (nonce?.Length == 0)
            {
                throw new Exception("You must provide a nonce to encrypt with Ascon 128");
            }
            if (key?.Length == 0)
            {
                throw new Exception("You must provide a key to encrypt with Ascon 128");
            }
            if (toEncrypt == null || toEncrypt.Length == 0)
            {
                throw new Exception("You must provide data to encrypt with Ascon 128");
            }

            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                Ascon128EncryptResultStruct encryptResult = AsconLinuxWrapper.ascon_128_encrypt_threadpool(nonce, nonce.Length, key, key.Length, toEncrypt, toEncrypt.Length);
                byte[] result = new byte[encryptResult.length];
                Marshal.Copy(encryptResult.ciphertext, result, 0, encryptResult.length);
                FreeMemoryHelper.FreeBytesMemory(encryptResult.ciphertext);
                DateTime end = DateTime.UtcNow;
                return result;
            }
            else
            {
                Ascon128EncryptResultStruct encryptResult = AsconWindowsWrapper.ascon_128_encrypt_threadpool(nonce, nonce.Length, key, key.Length, toEncrypt, toEncrypt.Length);
                byte[] result = new byte[encryptResult.length];
                Marshal.Copy(encryptResult.ciphertext, result, 0, encryptResult.length);
                FreeMemoryHelper.FreeBytesMemory(encryptResult.ciphertext);
                DateTime end = DateTime.UtcNow;
                return result;
            }
        }

        /// <summary>
        /// Decrypts with Ascond 128
        /// </summary>
        /// <param name="nonce"></param>
        /// <param name="key"></param>
        /// <param name="toDecrypt"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public byte[] Ascon128Decrypt(byte[] nonce, byte[] key, byte[] toDecrypt)
        {
            if (nonce?.Length == 0)
            {
                throw new Exception("You must provide a nonce to decrypt with Ascon 128");
            }
            if (key?.Length == 0)
            {
                throw new Exception("You must provide a key to decrypt with Ascon 128");
            }
            if (toDecrypt == null || toDecrypt.Length == 0)
            {
                throw new Exception("You must provide data to decrypt with Ascon 128");
            }

            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                Ascon128DecryptResultStruct decryptResult = AsconLinuxWrapper.ascon_128_decrypt(nonce, nonce.Length, key, key.Length, toDecrypt, toDecrypt.Length);
                byte[] result = new byte[decryptResult.length];
                Marshal.Copy(decryptResult.plaintext, result, 0, decryptResult.length);
                FreeMemoryHelper.FreeBytesMemory(decryptResult.plaintext);
                DateTime end = DateTime.UtcNow;
                return result;
            }
            else
            {
                Ascon128DecryptResultStruct decryptResult = AsconWindowsWrapper.ascon_128_decrypt(nonce, nonce.Length, key, key.Length, toDecrypt, toDecrypt.Length);
                byte[] result = new byte[decryptResult.length];
                Marshal.Copy(decryptResult.plaintext, result, 0, decryptResult.length);
                FreeMemoryHelper.FreeBytesMemory(decryptResult.plaintext);
                DateTime end = DateTime.UtcNow;
                return result;
            }
        }

        /// <summary>
        /// Decrypts with Ascond 128 on the threadpool
        /// </summary>
        /// <param name="nonce"></param>
        /// <param name="key"></param>
        /// <param name="toDecrypt"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public byte[] Ascon128DecryptThreadpool(byte[] nonce, byte[] key, byte[] toDecrypt)
        {
            if (!CASConfiguration.IsThreadingEnabled)
            {
                throw new Exception("You do not have the product subscription to work with the thread pool featues");
            }

            if (nonce?.Length == 0)
            {
                throw new Exception("You must provide a nonce to decrypt with Ascon 128");
            }
            if (key?.Length == 0)
            {
                throw new Exception("You must provide a key to decrypt with Ascon 128");
            }
            if (toDecrypt == null || toDecrypt.Length == 0)
            {
                throw new Exception("You must provide data to decrypt with Ascon 128");
            }

            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                Ascon128DecryptResultStruct decryptResult = AsconLinuxWrapper.ascon_128_decrypt_threadpool(nonce, nonce.Length, key, key.Length, toDecrypt, toDecrypt.Length);
                byte[] result = new byte[decryptResult.length];
                Marshal.Copy(decryptResult.plaintext, result, 0, decryptResult.length);
                FreeMemoryHelper.FreeBytesMemory(decryptResult.plaintext);
                DateTime end = DateTime.UtcNow;
                return result;
            }
            else
            {
                Ascon128DecryptResultStruct decryptResult = AsconWindowsWrapper.ascon_128_decrypt_threadpool(nonce, nonce.Length, key, key.Length, toDecrypt, toDecrypt.Length);
                byte[] result = new byte[decryptResult.length];
                Marshal.Copy(decryptResult.plaintext, result, 0, decryptResult.length);
                FreeMemoryHelper.FreeBytesMemory(decryptResult.plaintext);
                DateTime end = DateTime.UtcNow;
                return result;
            }
        }
    }
}
