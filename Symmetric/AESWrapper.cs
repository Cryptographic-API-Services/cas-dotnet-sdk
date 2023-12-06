using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace EasDotnetSdk
{
    public class AESWrapper
    {
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

        public async Task<AesEncrypt> Aes128EncryptAsync(string nonceKey, string dataToEncrypt)
        {
            return await Task.Run(() =>
            {
                return this.Aes128Encrypt(nonceKey, dataToEncrypt);
            });
        }

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
            return aes128_encrypt_string(nonceKey, dataToEncrypt);
        }

        public async Task<IntPtr> Aes128KeyAsync()
        {
            return await Task.Run(() =>
            {
                return this.Aes128Key();
            });
        }

        public IntPtr Aes128Key()
        {
            return aes_128_key();
        }
        public async Task<IntPtr> DecryptAES128WithKeyAsync(string nonceKey, string key, string dataToDecrypt)
        {
            return await Task.Run(() =>
            {
                return this.DecryptAES128WithKey(nonceKey, key, dataToDecrypt);
            });
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
            return aes128_decrypt_string(nonceKey, key, dataToDecrypt);
        }

        public async Task<IntPtr> EncryptAES128WithKeyAsync(string nonceKey, string key, string dataToEncrypt)
        {
            return await Task.Run(() =>
            {
                return this.EncryptAES128WithKey(nonceKey, key, dataToEncrypt);
            });
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
            return aes_128_encrypt_string_with_key(nonceKey, key, dataToEncrypt);
        }

        public async Task<IntPtr> EncryptWithKeyAsync(string nonceKey, string key, string dataToEncrypt)
        {
            return await Task.Run(() =>
            {
                return aes256_encrypt_string_with_key(nonceKey, key, dataToEncrypt);
            });
        }
        public IntPtr Aes256Key()
        {
            return aes_256_key();
        }

        public async Task<IntPtr> Aes256KeyAsync()
        {
            return await Task.Run(() =>
            {
                return aes_256_key();
            });
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
            if (!string.IsNullOrEmpty(nonceKey) && !string.IsNullOrEmpty(toEncrypt))
            {
                return aes256_encrypt_string(nonceKey, toEncrypt);
            }
            else
            {
                throw new Exception("You need to pass in a valid key and text string to encrypt");
            }
        }

        /// <summary>
        /// AES 256 encrypt
        /// </summary>
        /// <param name="nonceKey"></param>
        /// <param name="toEncrypt"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public async Task<AesEncrypt> EncryptPerformantAsync(string nonceKey, string toEncrypt)
        {
            if (!string.IsNullOrEmpty(nonceKey) && !string.IsNullOrEmpty(toEncrypt))
            {
                return await Task.Run(() =>
                {
                    return aes256_encrypt_string(nonceKey, toEncrypt);
                });
            }
            else
            {
                throw new Exception("You need to pass in a valid key and text string to encrypt");
            }
        }

        public IntPtr DecryptPerformant(string nonceKey, string key, string toDecrypt)
        {
            if (!string.IsNullOrEmpty(nonceKey) && !string.IsNullOrEmpty(key) && !string.IsNullOrEmpty(toDecrypt))
            {
                return aes256_decrypt_string(nonceKey, key, toDecrypt);
            }
            else
            {
                throw new Exception("You need to provide a nonce key, key, and data to decrypt to use AES-GCM");
            }
        }
        public async Task<IntPtr> DecryptPerformantAsync(string nonceKey, string key, string toDecrypt)
        {
            if (!string.IsNullOrEmpty(nonceKey) && !string.IsNullOrEmpty(key) && !string.IsNullOrEmpty(toDecrypt))
            {
                return await Task.Run(() =>
                {
                    return aes256_decrypt_string(nonceKey, key, toDecrypt);
                });
            }
            else
            {
                throw new Exception("You need to provide a nonce key, key, and data to decrypt to use AES-GCM");
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