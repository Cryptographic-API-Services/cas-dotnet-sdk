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
        public struct AesEncrypt
        {
            public IntPtr key { get; set; }
            public IntPtr ciphertext { get; set; }
        }

        [DllImport("performant_encryption.dll")]
        private static extern AesEncrypt aes256_encrypt_string(string nonceKey, string dataToEncrypt);
        [DllImport("performant_encryption.dll")]
        private static extern AesEncrypt aes128_encrypt_string(string nonceKey, string dataToEncrypt);
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

        public AesEncrypt Aes128Encrypt(string nonceKey, string dataToEncrypt)
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
            return aes128_encrypt_string(nonceKey, dataToEncrypt);
        }

        public IntPtr Aes128Key()
        {
            OSPlatform platform = this._operatingSystem.GetOperatingSystem();
            if (platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            return aes_128_key();
        }

        public IntPtr DecryptAES128WithKey(string nonceKey, string key, string dataToDecrypt)
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
            return aes128_decrypt_string(nonceKey, key, dataToDecrypt);
        }

        public IntPtr EncryptAES128WithKey(string nonceKey, string key, string dataToEncrypt)
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
            return aes_128_encrypt_string_with_key(nonceKey, key, dataToEncrypt);
        }
        public IntPtr Aes256Key()
        {
            OSPlatform platform = this._operatingSystem.GetOperatingSystem();
            if (platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            return aes_256_key();
        }

        /// <summary>
        /// AES 256 encrypt
        /// </summary>
        /// <param name="nonceKey"></param>
        /// <param name="toEncrypt"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>

        public AesEncrypt EncryptPerformant(string nonceKey, string toEncrypt)
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
            return aes256_encrypt_string(nonceKey, toEncrypt);
        }
        public IntPtr DecryptPerformant(string nonceKey, string key, string toDecrypt)
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
            return aes256_decrypt_string(nonceKey, key, toDecrypt);
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