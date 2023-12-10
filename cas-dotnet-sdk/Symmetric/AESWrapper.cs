using CasDotnetSdk.Helpers;
using CasDotnetSdk.Symmetric.Linux;
using CasDotnetSdk.Symmetric.Windows;
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace CasDotnetSdk.Symmetric
{
    public class AESWrapper
    {
        private readonly OSPlatform _platform;
        public AESWrapper()
        {
            this._platform = new OperatingSystemDeterminator().GetOperatingSystem();
        }
        public class AesEncryptResult
        {
            public string Key { get; set; }
            public string CipherText { get; set; }
        }
        internal struct AesEncryptStruct
        {
            public IntPtr key { get; set; }
            public IntPtr ciphertext { get; set; }
        }

        public AesEncryptResult Aes128Encrypt(string nonceKey, string dataToEncrypt)
        {
            if (string.IsNullOrEmpty(nonceKey))
            {
                throw new Exception("Please provide a nonce key to encrypt with AES-128");
            }
            if (string.IsNullOrEmpty(dataToEncrypt))
            {
                throw new Exception("Please provide data to encrypt with AES-128");
            }

            if (this._platform == OSPlatform.Linux)
            {
                AesEncryptStruct encryptStruct = AESLinuxWrapper.aes128_encrypt_string(nonceKey, dataToEncrypt);
                AesEncryptResult result = new AesEncryptResult()
                {
                    CipherText = Marshal.PtrToStringAnsi(encryptStruct.ciphertext),
                    Key = Marshal.PtrToStringAnsi(encryptStruct.key)
                };
                AESLinuxWrapper.free_cstring(encryptStruct.key);
                AESLinuxWrapper.free_cstring(encryptStruct.ciphertext);
                return result;
            }
            else
            {
                AesEncryptStruct encryptStruct = AESWindowsWrapper.aes128_encrypt_string(nonceKey, dataToEncrypt);
                AesEncryptResult result = new AesEncryptResult()
                {
                    CipherText = Marshal.PtrToStringAnsi(encryptStruct.ciphertext),
                    Key = Marshal.PtrToStringAnsi(encryptStruct.key),
                };
                AESWindowsWrapper.free_cstring(encryptStruct.key);
                AESWindowsWrapper.free_cstring(encryptStruct.ciphertext);
                return result;
            }
        }

        public string Aes128Key()
        {
            if (this._platform == OSPlatform.Linux)
            {
                IntPtr keyPtr = AESLinuxWrapper.aes_128_key();
                string key = Marshal.PtrToStringAnsi(keyPtr);
                AESLinuxWrapper.free_cstring(keyPtr);
                return key;
            }
            else
            {
                IntPtr keyPtr = AESWindowsWrapper.aes_128_key();
                string key = Marshal.PtrToStringAnsi(keyPtr);
                AESWindowsWrapper.free_cstring(keyPtr);
                return key;
            }
        }

        public string DecryptAES128WithKey(string nonceKey, string key, string dataToDecrypt)
        {
            if (string.IsNullOrEmpty(nonceKey))
            {
                throw new Exception("Please provide an IV to decrypt with AES-128");
            }
            if (string.IsNullOrEmpty(key))
            {
                throw new Exception("Please provide a secret key to decrypt with AES-128");
            }
            if (string.IsNullOrEmpty(dataToDecrypt))
            {
                throw new Exception("Please provide a data to decrypt with AES-128");
            }

            if (this._platform == OSPlatform.Linux)
            {
                IntPtr decryptPtr = AESLinuxWrapper.aes128_decrypt_string(nonceKey, key, dataToDecrypt);
                string decrypted = Marshal.PtrToStringAnsi(decryptPtr);
                AESLinuxWrapper.free_cstring(decryptPtr);
                return decrypted;
            }
            else
            {
                IntPtr decryptPtr = AESWindowsWrapper.aes128_decrypt_string(nonceKey, key, dataToDecrypt);
                string decrypted = Marshal.PtrToStringAnsi(decryptPtr);
                AESWindowsWrapper.free_cstring(decryptPtr);
                return decrypted;
            }
        }

        public string EncryptAES128WithKey(string nonceKey, string key, string dataToEncrypt)
        {
            if (string.IsNullOrEmpty(nonceKey))
            {
                throw new Exception("Please provide an IV to encrypt with AES-128");
            }
            if (string.IsNullOrEmpty(key))
            {
                throw new Exception("Please provide a secret key to encrypt with AES-128");
            }
            if (string.IsNullOrEmpty(dataToEncrypt))
            {
                throw new Exception("Please provide a data to encrypt with AES-128");
            }

            if (this._platform == OSPlatform.Linux)
            {
                IntPtr encryptedPtr = AESLinuxWrapper.aes_128_encrypt_string_with_key(nonceKey, key, dataToEncrypt);
                string encrypted = Marshal.PtrToStringAnsi(encryptedPtr);
                AESLinuxWrapper.free_cstring(encryptedPtr);
                return encrypted;
            }
            else
            {
                IntPtr encryptedPtr = AESWindowsWrapper.aes_128_encrypt_string_with_key(nonceKey, key, dataToEncrypt);
                string encrypted = Marshal.PtrToStringAnsi(encryptedPtr);
                AESWindowsWrapper.free_cstring(encryptedPtr);
                return encrypted;
            }
        }
        public string Aes256Key()
        {
            if (this._platform == OSPlatform.Linux)
            {
                IntPtr keyPtr = AESLinuxWrapper.aes_256_key();
                string key = Marshal.PtrToStringAnsi(keyPtr);
                AESLinuxWrapper.free_cstring(keyPtr);
                return key;
            }
            else
            {
                IntPtr keyPtr = AESWindowsWrapper.aes_256_key();
                string key = Marshal.PtrToStringAnsi(keyPtr);
                AESWindowsWrapper.free_cstring(keyPtr);
                return key;
            }
        }

        /// <summary>
        /// AES 256 encrypt
        /// </summary>
        /// <param name="nonceKey"></param>
        /// <param name="toEncrypt"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>

        public AesEncryptResult Aes256Encrypt(string nonceKey, string toEncrypt)
        {
            if (string.IsNullOrEmpty(nonceKey))
            {
                throw new Exception("You must provide a nonce key for AES 256");
            }
            if (string.IsNullOrEmpty(toEncrypt))
            {
                throw new Exception("You must provide data to encrypt for AES 256");
            }

            if (this._platform == OSPlatform.Linux)
            {
                AesEncryptStruct encryptStruct = AESLinuxWrapper.aes256_encrypt_string(nonceKey, toEncrypt);
                AesEncryptResult result = new AesEncryptResult()
                {
                    CipherText = Marshal.PtrToStringAnsi(encryptStruct.ciphertext),
                    Key = Marshal.PtrToStringAnsi(encryptStruct.key)
                };
                AESLinuxWrapper.free_cstring(encryptStruct.key);
                AESLinuxWrapper.free_cstring(encryptStruct.ciphertext);
                return result;
            }
            else
            {
                AesEncryptStruct encryptStruct = AESWindowsWrapper.aes256_encrypt_string(nonceKey, toEncrypt);
                AesEncryptResult result = new AesEncryptResult()
                {
                    CipherText = Marshal.PtrToStringAnsi(encryptStruct.ciphertext),
                    Key = Marshal.PtrToStringAnsi(encryptStruct.key)
                };
                AESWindowsWrapper.free_cstring(encryptStruct.key);
                AESWindowsWrapper.free_cstring(encryptStruct.ciphertext);
                return result;
            }
        }
        public string Aes256Decrypt(string nonceKey, string key, string toDecrypt)
        {
            if (string.IsNullOrEmpty(nonceKey))
            {
                throw new Exception("You must provide a nonce key to decrypt with AES 256");
            }
            if (string.IsNullOrEmpty(key))
            {
                throw new Exception("You must provide a key to decrypt with AES 256");
            }
            if (string.IsNullOrEmpty(toDecrypt))
            {
                throw new Exception("You must provide data to decrypt with AES 256");
            }

            if (this._platform == OSPlatform.Linux)
            {
                IntPtr decryptPtr = AESLinuxWrapper.aes256_decrypt_string(nonceKey, key, toDecrypt);
                string decrypt = Marshal.PtrToStringAnsi(decryptPtr);
                AESLinuxWrapper.free_cstring(decryptPtr);
                return decrypt;
            }
            else
            {
                IntPtr decryptPtr = AESWindowsWrapper.aes256_decrypt_string(nonceKey, key, toDecrypt);
                string decrypt = Marshal.PtrToStringAnsi(decryptPtr);
                AESWindowsWrapper.free_cstring(decryptPtr);
                return decrypt;
            }
        }
        public string GenerateAESNonce()
        {
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            byte[] nonceBytes = new byte[12];
            rng.GetBytes(nonceBytes);
            return BitConverter.ToString(nonceBytes).Substring(0, 12);
        }
    }
}