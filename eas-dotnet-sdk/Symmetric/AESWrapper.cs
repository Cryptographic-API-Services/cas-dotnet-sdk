using EasDotnetSdk.Helpers;
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace EasDotnetSdk.Symmetric
{
    public class AESWrapper
    {
        private readonly OperatingSystemDeterminator _operatingSystem;
        public AESWrapper()
        {
            this._operatingSystem = new OperatingSystemDeterminator();
        }
        public class AesEncryptResult
        {
            public string Key { get; set; }
            public string CipherText { get; set; }
        }
        private struct AesEncryptStruct
        {
            public IntPtr key { get; set; }
            public IntPtr ciphertext { get; set; }
        }

        [DllImport("performant_encryption.dll")]
        private static extern AesEncryptStruct aes256_encrypt_string(string nonceKey, string dataToEncrypt);
        [DllImport("performant_encryption.dll")]
        private static extern AesEncryptStruct aes128_encrypt_string(string nonceKey, string dataToEncrypt);
        [DllImport("performant_encryption.dll")]
        private static extern IntPtr aes256_decrypt_string(string nonceKey, string key, string dataToDecrypt);
        [DllImport("performant_encryption.dll")]
        private static extern IntPtr aes_256_key();
        [DllImport("performant_encryption.dll")]
        private static extern IntPtr aes_128_key();
        [DllImport("performant_encryption.dll")]
        private static extern IntPtr aes256_encrypt_string_with_key(string nonceKey, string key, string dataToEncrypt);
        [DllImport("performant_encryption.dll")]
        private static extern IntPtr aes_128_encrypt_string_with_key(string nonceKey, string key, string dataToEncrypt);
        [DllImport("performant_encryption.dll")]
        private static extern IntPtr aes128_decrypt_string(string nonceKey, string key, string dataToEncrypt);

        [DllImport("performant_encryption.dll")]
        public static extern void free_cstring(IntPtr stringToFree);

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
            OSPlatform platform = this._operatingSystem.GetOperatingSystem();
            if (platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            AesEncryptStruct encryptStruct = aes128_encrypt_string(nonceKey, dataToEncrypt);
            AesEncryptResult result = new AesEncryptResult()
            {
                CipherText = Marshal.PtrToStringAnsi(encryptStruct.ciphertext),
                Key = Marshal.PtrToStringAnsi(encryptStruct.key)
            };
            AESWrapper.free_cstring(encryptStruct.key);
            AESWrapper.free_cstring(encryptStruct.ciphertext);
            return result;
        }

        public string Aes128Key()
        {
            OSPlatform platform = this._operatingSystem.GetOperatingSystem();
            if (platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            IntPtr keyPtr = aes_128_key();
            string key = Marshal.PtrToStringAnsi(keyPtr);
            AESWrapper.free_cstring(keyPtr);
            return key;
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
            OSPlatform platform = this._operatingSystem.GetOperatingSystem();
            if (platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            IntPtr decryptPtr = aes128_decrypt_string(nonceKey, key, dataToDecrypt);
            string decrypted = Marshal.PtrToStringAnsi(decryptPtr);
            AESWrapper.free_cstring(decryptPtr);
            return decrypted;
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
            OSPlatform platform = this._operatingSystem.GetOperatingSystem();
            if (platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            IntPtr encryptedPtr = aes_128_encrypt_string_with_key(nonceKey, key, dataToEncrypt);
            string encrypted = Marshal.PtrToStringAnsi(encryptedPtr);
            AESWrapper.free_cstring(encryptedPtr);
            return encrypted;
        }
        public string Aes256Key()
        {
            OSPlatform platform = this._operatingSystem.GetOperatingSystem();
            if (platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            IntPtr keyPtr = aes_256_key();
            string key = Marshal.PtrToStringAnsi(keyPtr);
            AESWrapper.free_cstring(keyPtr);
            return key;
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
            OSPlatform platform = this._operatingSystem.GetOperatingSystem();
            if (platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            AesEncryptStruct encryptStruct = aes256_encrypt_string(nonceKey, toEncrypt);
            AesEncryptResult result = new AesEncryptResult()
            {
                CipherText = Marshal.PtrToStringAnsi(encryptStruct.ciphertext),
                Key = Marshal.PtrToStringAnsi(encryptStruct.key)
            };
            AESWrapper.free_cstring(encryptStruct.key);
            AESWrapper.free_cstring(encryptStruct.ciphertext);
            return result;
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
            OSPlatform platform = this._operatingSystem.GetOperatingSystem();
            if (platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            IntPtr decryptPtr = aes256_decrypt_string(nonceKey, key, toDecrypt);
            string decrypt = Marshal.PtrToStringAnsi(decryptPtr);
            AESWrapper.free_cstring(decryptPtr);
            return decrypt;
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