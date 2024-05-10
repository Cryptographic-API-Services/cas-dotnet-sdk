using CasDotnetSdk.Asymmetric;
using CasDotnetSdk.Http;
using CasDotnetSdk.Hybrid.Types;
using CasDotnetSdk.Symmetric;
using CASHelpers;
using CASHelpers.Types.HttpResponses.BenchmarkAPI;
using System;
using System.Reflection;

namespace CasDotnetSdk.Hybrid
{
    /// <summary>
    /// In CAS, Hybrid encryption is a combination of RSA Encryption for the AES-GCM key.
    /// The user is expected to generate an RSA key pair and AES Key and Nonce before hand if they want to utilize using the same key for multiple data sets
    /// Eventually we may want to move this logic directly into cas-core-lib.
    /// </summary>
    public class HybridEncryptionWrapper
    {
        private readonly BenchmarkSender _benchmarkSender;
        private readonly AESWrapper _aesWrapper;
        private readonly RSAWrapper _rsaWrapper;

        public HybridEncryptionWrapper()
        {
            this._benchmarkSender = new BenchmarkSender();
            this._aesWrapper = new AESWrapper();
            this._rsaWrapper = new RSAWrapper();
        }

        public AESRSAHybridEncryptResult EncryptAESRSAHybrid(byte[] dataToEncrypt, AESRSAHybridInitializer initilizer)
        {
            DateTime start = DateTime.UtcNow;
            byte[] aesEncryptResult = (initilizer.AesType == 128)
                ? this._aesWrapper.Aes128Encrypt(initilizer.AesNonce, initilizer.AesKey, dataToEncrypt)
                : this._aesWrapper.Aes256Encrypt(initilizer.AesNonce, initilizer.AesKey, dataToEncrypt);
            byte[] encryptedAesKey = this._rsaWrapper.RsaEncryptBytes(initilizer.RsaKeyPair.PublicKey, Convert.FromBase64String(initilizer.AesKey));
            AESRSAHybridEncryptResult result = new AESRSAHybridEncryptResult()
            {
                CipherText = aesEncryptResult,
                EncryptedAesKey = encryptedAesKey,
                AesType = initilizer.AesType,
                AesNonce = initilizer.AesNonce,
            };
            DateTime end = DateTime.UtcNow;
            this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(HybridEncryptionWrapper));
            return result;
        }

        public byte[] DecryptAESRSAHybrid(string rsaPrivateKey, AESRSAHybridEncryptResult encryptResult)
        {
            if (!RSAValidator.ValidateRsaPemKey(rsaPrivateKey))
            {
                throw new Exception("Must provide a RSA Private Key to decrypt with AES RSA Hybrid Encryption");
            }
            DateTime start = DateTime.UtcNow;
            byte[] plaintextAesKey = this._rsaWrapper.RsaDecryptBytes(rsaPrivateKey, encryptResult.EncryptedAesKey);
            byte[] plaintext = (encryptResult.AesType == 128)
                ? this._aesWrapper.Aes128Decrypt(encryptResult.AesNonce, Convert.ToBase64String(plaintextAesKey), encryptResult.CipherText)
                : this._aesWrapper.Aes256Decrypt(encryptResult.AesNonce, Convert.ToBase64String(plaintextAesKey), encryptResult.CipherText);
            DateTime end = DateTime.UtcNow;
            this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(HybridEncryptionWrapper));
            return plaintext;
        }
    }
}