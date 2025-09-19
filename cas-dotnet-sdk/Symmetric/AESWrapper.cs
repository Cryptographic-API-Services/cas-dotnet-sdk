using CasDotnetSdk.Helpers;
using CasDotnetSdk.Http;
using CasDotnetSdk.Symmetric.Linux;
using CasDotnetSdk.Symmetric.Types;
using CasDotnetSdk.Symmetric.Windows;
using CASHelpers;
using CASHelpers.Types.HttpResponses.BenchmarkAPI;
using System;
using System.Reflection;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Symmetric
{
    public class AESWrapper : BaseWrapper
    {
        private readonly OSPlatform _platform;
        private readonly BenchmarkSender _sender;

        /// <summary>
        /// A wrapper class for AES-GCM 128 and 256 bit encryption and decryption.
        /// </summary>
        public AESWrapper()
        {
            this._platform = new OperatingSystemDeterminator().GetOperatingSystem();
            this._sender = new BenchmarkSender();
        }

        /// <summary>
        /// Generates an AES 128 bit key.
        /// </summary>
        /// <returns></returns>
        public byte[] Aes128Key()
        {
            DateTime start = DateTime.UtcNow;
            AesKeyResult keyResult = (this._platform == OSPlatform.Linux) ? AESLinuxWrapper.aes_128_key() : AESWindowsWrapper.aes_128_key();
            byte[] key = new byte[keyResult.length];
            Marshal.Copy(keyResult.key, key, 0, keyResult.length);
            FreeMemoryHelper.FreeBytesMemory(keyResult.key);
            DateTime end = DateTime.UtcNow;
            this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Symmetric, nameof(AESWrapper));
            return key;
        }

        /// <summary>
        /// Generates an AES 256 bit key.
        /// </summary>
        /// <returns></returns>
        public byte[] Aes256Key()
        {
            DateTime start = DateTime.UtcNow;
            AesKeyResult keyResult = (this._platform == OSPlatform.Linux) ? AESLinuxWrapper.aes_256_key() : AESWindowsWrapper.aes_256_key();
            byte[] key = new byte[keyResult.length];
            Marshal.Copy(keyResult.key, key, 0, keyResult.length);
            FreeMemoryHelper.FreeBytesMemory(keyResult.key);
            DateTime end = DateTime.UtcNow;
            this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Symmetric, nameof(AESWrapper));
            return key;
        }

        /// <summary>
        /// Generates an AES 256 bit key and nonce based off a X25519 Diffie Hellman shared secret.
        /// </summary>
        /// <param name="sharedSecret"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>

        public Aes256KeyAndNonceX25519DiffieHellman Aes256KeyNonceX25519DiffieHellman(byte[] sharedSecret)
        {
            if (sharedSecret == null || sharedSecret.Length == 0)
            {
                throw new Exception("You must provide allocated data for X25519 shared secret to generate an AES Key");
            }

            DateTime start = DateTime.UtcNow;
            Aes256KeyAndNonceX25519DiffieHellmanStruct result = (this._platform == OSPlatform.Linux) ?
                AESLinuxWrapper.aes_256_key_and_nonce_from_x25519_diffie_hellman_shared_secret(sharedSecret, sharedSecret.Length) :
                AESWindowsWrapper.aes_256_key_and_nonce_from_x25519_diffie_hellman_shared_secret(sharedSecret, sharedSecret.Length);
            byte[] aesKey = new byte[result.aes_key_ptr_length];
            Marshal.Copy(result.aes_key_ptr, aesKey, 0, result.aes_key_ptr_length);
            FreeMemoryHelper.FreeBytesMemory(result.aes_key_ptr);
            byte[] aesNonce = new byte[result.aes_nonce_ptr_length];
            Marshal.Copy(result.aes_nonce_ptr, aesNonce, 0, result.aes_nonce_ptr_length);
            FreeMemoryHelper.FreeBytesMemory(result.aes_nonce_ptr);
            Aes256KeyAndNonceX25519DiffieHellman keyAndNonce = new Aes256KeyAndNonceX25519DiffieHellman()
            {
                AesKey = aesKey,
                AesNonce = aesNonce
            };
            DateTime end = DateTime.UtcNow;
            this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Symmetric, nameof(AESWrapper));
            return keyAndNonce;
        }

        /// <summary>
        /// Generates an AES 128 bit key and nonce based off a X25519 Diffie Hellman shared secret.
        /// </summary>
        /// <param name="sharedSecret"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public Aes256KeyAndNonceX25519DiffieHellman Aes128KeyNonceX25519DiffieHellman(byte[] sharedSecret)
        {
            if (sharedSecret == null || sharedSecret.Length == 0)
            {
                throw new Exception("You must provide allocated data for X25519 shared secret to generate an AES Key");
            }

            DateTime start = DateTime.UtcNow;
            Aes256KeyAndNonceX25519DiffieHellmanStruct result = (this._platform == OSPlatform.Linux) ?
                AESLinuxWrapper.aes_128_key_and_nonce_from_x25519_diffie_hellman_shared_secret(sharedSecret, sharedSecret.Length) :
                AESWindowsWrapper.aes_128_key_and_nonce_from_x25519_diffie_hellman_shared_secret(sharedSecret, sharedSecret.Length);
            byte[] aesKey = new byte[result.aes_key_ptr_length];
            Marshal.Copy(result.aes_key_ptr, aesKey, 0, result.aes_key_ptr_length);
            FreeMemoryHelper.FreeCStringMemory(result.aes_key_ptr);
            byte[] aesNonce = new byte[result.aes_nonce_ptr_length];
            Marshal.Copy(result.aes_nonce_ptr, aesNonce, 0, result.aes_nonce_ptr_length);
            FreeMemoryHelper.FreeBytesMemory(result.aes_nonce_ptr);
            Aes256KeyAndNonceX25519DiffieHellman keyAndNonce = new Aes256KeyAndNonceX25519DiffieHellman()
            {
                AesKey = aesKey,
                AesNonce = aesNonce
            };
            DateTime end = DateTime.UtcNow;
            this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Symmetric, nameof(AESWrapper));
            return keyAndNonce;
        }

        /// <summary>
        /// Encrypts with AES-256-GCM.
        /// </summary>
        /// <param name="nonceKey"></param>
        /// <param name="key"></param>
        /// <param name="toEncrypt"></param>
        /// <param name="sendBenchmark"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public byte[] Aes256Encrypt(byte[] nonceKey, byte[] key, byte[] toEncrypt, bool sendBenchmark = true)
        {
            if (nonceKey?.Length == 0)
            {
                throw new Exception("You must provide a nonce to encrypt with AES 256");
            }
            if (key?.Length == 0)
            {
                throw new Exception("You must provide a key  to encrypt with AES 256");
            }
            if (toEncrypt == null || toEncrypt.Length <= 0)
            {
                throw new Exception("You must provide allocated data to encrypt with AES 256");
            }

            DateTime start = DateTime.UtcNow;
            AesBytesEncrypt encryptResult = (this._platform == OSPlatform.Linux) ?
                AESLinuxWrapper.aes_256_encrypt_bytes_with_key(nonceKey, nonceKey.Length, key, key.Length, toEncrypt, toEncrypt.Length) :
                AESWindowsWrapper.aes_256_encrypt_bytes_with_key(nonceKey, nonceKey.Length, key, key.Length, toEncrypt, toEncrypt.Length);
            byte[] result = new byte[encryptResult.length];
            Marshal.Copy(encryptResult.ciphertext, result, 0, encryptResult.length);
            FreeMemoryHelper.FreeBytesMemory(encryptResult.ciphertext);
            DateTime end = DateTime.UtcNow;
            if (sendBenchmark)
                this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Symmetric, nameof(AESWrapper));
            return result;
        }



        /// <summary>
        /// Decrypts with AES-256-GCM.
        /// </summary>
        /// <param name="nonceKey"></param>
        /// <param name="key"></param>
        /// <param name="toDecrypt"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public byte[] Aes256Decrypt(byte[] nonceKey, byte[] key, byte[] toDecrypt)
        {
            if (nonceKey?.Length == 0)
            {
                throw new Exception("You must provide a nonce to decrypt with AES 256");
            }
            if (key?.Length == 0)
            {
                throw new Exception("You must provide a key  to decrypt with AES 256");
            }
            if (toDecrypt == null || toDecrypt.Length <= 0)
            {
                throw new Exception("You must provide allocated data to decrypt with AES 256");
            }

            DateTime start = DateTime.UtcNow;
            AesBytesDecrypt encryptResult = (this._platform == OSPlatform.Linux) ?
                AESLinuxWrapper.aes_256_decrypt_bytes_with_key(nonceKey, nonceKey.Length, key, key.Length, toDecrypt, toDecrypt.Length) :
                AESWindowsWrapper.aes_256_decrypt_bytes_with_key(nonceKey, nonceKey.Length, key, key.Length, toDecrypt, toDecrypt.Length);
            byte[] result = new byte[encryptResult.length];
            Marshal.Copy(encryptResult.plaintext, result, 0, encryptResult.length);
            FreeMemoryHelper.FreeBytesMemory(encryptResult.plaintext);
            DateTime end = DateTime.UtcNow;
            this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Symmetric, nameof(AESWrapper));
            return result;
        }

        /// <summary>
        /// Encrypts with AES-128-GCM.
        /// </summary>
        /// <param name="nonceKey"></param>
        /// <param name="key"></param>
        /// <param name="dataToEncrypt"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public byte[] Aes128Encrypt(byte[] nonceKey, byte[] key, byte[] dataToEncrypt)
        {
            if (nonceKey?.Length == 0)
            {
                throw new Exception("You must provide a nonce key to encrypt with AES 128");
            }
            if (key?.Length == 0)
            {
                throw new Exception("You must provide a key to encrypt with AES 128");
            }
            if (dataToEncrypt == null || dataToEncrypt?.Length == 0)
            {
                throw new Exception("You must provide allocated data to encrypt with AES 128");
            }

            DateTime start = DateTime.UtcNow;
            AesBytesEncrypt encryptResult = (this._platform == OSPlatform.Linux) ?
                AESLinuxWrapper.aes_128_encrypt_bytes_with_key(nonceKey, nonceKey.Length, key, key.Length, dataToEncrypt, dataToEncrypt.Length) :
                AESWindowsWrapper.aes_128_encrypt_bytes_with_key(nonceKey, nonceKey.Length, key, key.Length, dataToEncrypt, dataToEncrypt.Length);
            byte[] result = new byte[encryptResult.length];
            Marshal.Copy(encryptResult.ciphertext, result, 0, encryptResult.length);
            FreeMemoryHelper.FreeBytesMemory(encryptResult.ciphertext);
            DateTime end = DateTime.UtcNow;
            this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Symmetric, nameof(AESWrapper));
            return result;
        }

        /// <summary>
        /// Decrypts with AES-128-GCM.
        /// </summary>
        /// <param name="nonceKey"></param>
        /// <param name="key"></param>
        /// <param name="dataToDecrypt"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public byte[] Aes128Decrypt(byte[] nonceKey, byte[] key, byte[] dataToDecrypt)
        {
            if (nonceKey?.Length == 0)
            {
                throw new Exception("You must provide a nonce key to decrypt with AES 128");
            }
            if (key?.Length == 0)
            {
                throw new Exception("You must provide a key to decrypt with AES 128");
            }
            if (dataToDecrypt?.Length == 0)
            {
                throw new Exception("You must provide allocated data to decrypt with AES 128");
            }
            DateTime start = DateTime.UtcNow;
            AesBytesDecrypt decryptResult = (this._platform == OSPlatform.Linux) ?
                AESLinuxWrapper.aes_128_decrypt_bytes_with_key(nonceKey, nonceKey.Length, key, key.Length, dataToDecrypt, dataToDecrypt.Length) :
                AESWindowsWrapper.aes_128_decrypt_bytes_with_key(nonceKey, nonceKey.Length, key, key.Length, dataToDecrypt, dataToDecrypt.Length);
            byte[] result = new byte[decryptResult.length];
            Marshal.Copy(decryptResult.plaintext, result, 0, decryptResult.length);
            FreeMemoryHelper.FreeBytesMemory(decryptResult.plaintext);
            DateTime end = DateTime.UtcNow;
            this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Symmetric, nameof(AESWrapper));
            return result;
        }

        /// <summary>
        /// Generates a AES Nonce usuable for AES-128-GCM and AES-256-GCM.
        /// </summary>
        /// <returns></returns>
        public byte[] GenerateAESNonce()
        {
            DateTime start = DateTime.UtcNow;
            AesNonceResult nonceResult = (this._platform == OSPlatform.Linux) ? AESLinuxWrapper.aes_nonce() : AESWindowsWrapper.aes_nonce();
            byte[] result = new byte[nonceResult.length];
            Marshal.Copy(nonceResult.nonce, result, 0, nonceResult.length);
            FreeMemoryHelper.FreeBytesMemory(nonceResult.nonce);
            DateTime end = DateTime.UtcNow;
            this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Symmetric, nameof(AESWrapper));
            return result;
        }
    }
}