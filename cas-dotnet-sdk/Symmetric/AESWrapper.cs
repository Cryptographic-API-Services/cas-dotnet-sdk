using CasDotnetSdk.Http;
using CasDotnetSdk.Signatures;
using CasDotnetSdk.Symmetric.Linux;
using CasDotnetSdk.Symmetric.Types;
using CasDotnetSdk.Symmetric.Windows;
using CASHelpers;
using CASHelpers.Types.HttpResponses.BenchmarkAPI;
using System;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace CasDotnetSdk.Symmetric
{
    public class AESWrapper
    {
        private readonly OSPlatform _platform;
        private readonly BenchmarkSender _benchmarkSender;
        public AESWrapper()
        {
            this._platform = new OperatingSystemDeterminator().GetOperatingSystem();
            this._benchmarkSender = new BenchmarkSender();
        }

        public string Aes128Key()
        {
            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                IntPtr keyPtr = AESLinuxWrapper.aes_128_key();
                string key = Marshal.PtrToStringAnsi(keyPtr);
                AESLinuxWrapper.free_cstring(keyPtr);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(AESWrapper));
                return key;
            }
            else
            {
                IntPtr keyPtr = AESWindowsWrapper.aes_128_key();
                string key = Marshal.PtrToStringAnsi(keyPtr);
                AESWindowsWrapper.free_cstring(keyPtr);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(ED25519Wrapper));
                return key;
            }
        }
        public string Aes256Key()
        {
            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                IntPtr keyPtr = AESLinuxWrapper.aes_256_key();
                string key = Marshal.PtrToStringAnsi(keyPtr);
                AESLinuxWrapper.free_cstring(keyPtr);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(ED25519Wrapper));
                return key;
            }
            else
            {
                IntPtr keyPtr = AESWindowsWrapper.aes_256_key();
                string key = Marshal.PtrToStringAnsi(keyPtr);
                AESWindowsWrapper.free_cstring(keyPtr);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(ED25519Wrapper));
                return key;
            }
        }

        public byte[] Aes256EncryptBytes(string nonceKey, string key, byte[] toEncrypt)
        {
            if (string.IsNullOrEmpty(nonceKey))
            {
                throw new Exception("You must provide a nonce to encrypt with AES 256");
            }
            if (string.IsNullOrEmpty(key))
            {
                throw new Exception("You must provide a key  to encrypt with AES 256");
            }
            if (toEncrypt == null || toEncrypt.Length <= 0)
            {
                throw new Exception("You must provide allocated data to encrypt with AES 256");
            }

            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                AesBytesEncrypt encryptResult = AESLinuxWrapper.aes_256_encrypt_bytes_with_key(nonceKey, key, toEncrypt, toEncrypt.Length);
                byte[] result = new byte[encryptResult.length];
                Marshal.Copy(encryptResult.ciphertext, result, 0, encryptResult.length);
                AESLinuxWrapper.free_bytes(encryptResult.ciphertext);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(ED25519Wrapper));
                return result;
            }
            else
            {
                AesBytesEncrypt encryptResult = AESWindowsWrapper.aes_256_encrypt_bytes_with_key(nonceKey, key, toEncrypt, toEncrypt.Length);
                byte[] result = new byte[encryptResult.length];
                Marshal.Copy(encryptResult.ciphertext, result, 0, encryptResult.length);
                AESWindowsWrapper.free_bytes(encryptResult.ciphertext);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(ED25519Wrapper));
                return result;
            }
        }

        public byte[] Aes256DecryptBytes(string nonceKey, string key, byte[] toDecrypt)
        {
            if (string.IsNullOrEmpty(nonceKey))
            {
                throw new Exception("You must provide a nonce to decrypt with AES 256");
            }
            if (string.IsNullOrEmpty(key))
            {
                throw new Exception("You must provide a key  to decrypt with AES 256");
            }
            if (toDecrypt == null || toDecrypt.Length <= 0)
            {
                throw new Exception("You must provide allocated data to decrypt with AES 256");
            }

            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                AesBytesDecrypt encryptResult = AESLinuxWrapper.aes_256_decrypt_bytes_with_key(nonceKey, key, toDecrypt, toDecrypt.Length);
                byte[] result = new byte[encryptResult.length];
                Marshal.Copy(encryptResult.plaintext, result, 0, encryptResult.length);
                AESLinuxWrapper.free_bytes(encryptResult.plaintext);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(ED25519Wrapper));
                return result;
            }
            else
            {
                AesBytesDecrypt encryptResult = AESWindowsWrapper.aes_256_decrypt_bytes_with_key(nonceKey, key, toDecrypt, toDecrypt.Length);
                byte[] result = new byte[encryptResult.length];
                Marshal.Copy(encryptResult.plaintext, result, 0, encryptResult.length);
                AESWindowsWrapper.free_bytes(encryptResult.plaintext);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(ED25519Wrapper));
                return result;
            }
        }

        public byte[] Aes128BytesEncrypt(string nonceKey, string key, byte[] dataToEncrypt)
        {
            if (string.IsNullOrEmpty(nonceKey))
            {
                throw new Exception("You must provide a nonce key to encrypt with AES 128");
            }
            if (string.IsNullOrEmpty(key))
            {
                throw new Exception("You must provide a key to encrypt with AES 128");
            }
            if (dataToEncrypt == null || dataToEncrypt?.Length == 0)
            {
                throw new Exception("You must provide allocated data to encrypt with AES 128");
            }

            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                AesBytesEncrypt encryptResult = AESLinuxWrapper.aes_128_encrypt_bytes_with_key(nonceKey, key, dataToEncrypt, dataToEncrypt.Length);
                byte[] result = new byte[encryptResult.length];
                Marshal.Copy(encryptResult.ciphertext, result, 0, encryptResult.length);
                AESLinuxWrapper.free_bytes(encryptResult.ciphertext);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(ED25519Wrapper));
                return result;
            }
            else
            {
                AesBytesEncrypt encryptResult = AESWindowsWrapper.aes_128_encrypt_bytes_with_key(nonceKey, key, dataToEncrypt, dataToEncrypt.Length);
                byte[] result = new byte[encryptResult.length];
                Marshal.Copy(encryptResult.ciphertext, result, 0, encryptResult.length);
                AESWindowsWrapper.free_bytes(encryptResult.ciphertext);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(ED25519Wrapper));
                return result;
            }
        }

        public byte[] Aes128BytesDecrypt(string nonceKey, string key, byte[] dataToDecrypt)
        {
            if (string.IsNullOrEmpty(nonceKey))
            {
                throw new Exception("You must provide a nonce key to decrypt with AES 128");
            }
            if (string.IsNullOrEmpty(key))
            {
                throw new Exception("You must provide a key to decrypt with AES 128");
            }
            if (dataToDecrypt?.Length == 0)
            {
                throw new Exception("You must provide allocated data to decrypt with AES 128");
            }

            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                AesBytesDecrypt decryptResult = AESLinuxWrapper.aes_128_decrypt_bytes_with_key(nonceKey, key, dataToDecrypt, dataToDecrypt.Length);
                byte[] result = new byte[decryptResult.length];
                Marshal.Copy(decryptResult.plaintext, result, 0, decryptResult.length);
                AESLinuxWrapper.free_bytes(decryptResult.plaintext);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(ED25519Wrapper));
                return result;
            }
            else
            {
                AesBytesDecrypt decryptResult = AESWindowsWrapper.aes_128_decrypt_bytes_with_key(nonceKey, key, dataToDecrypt, dataToDecrypt.Length);
                byte[] result = new byte[decryptResult.length];
                Marshal.Copy(decryptResult.plaintext, result, 0, decryptResult.length);
                AESWindowsWrapper.free_bytes(decryptResult.plaintext);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(ED25519Wrapper));
                return result;
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