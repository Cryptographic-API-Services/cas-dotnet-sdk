using CasDotnetSdk.Asymmetric;
using CasDotnetSdk.Symmetric;
using System;
using System.Runtime.InteropServices;
using static CasDotnetSdk.Asymmetric.RSAWrapper;
using static CasDotnetSdk.Symmetric.AESWrapper;

namespace CasDotnetSdk.Hybrid
{
    public class AESRSAHybridWrapper
    {
        private readonly OSPlatform _platform;
        private readonly AESWrapper _aesWrapper;
        private readonly RSAWrapper _rsaWrapper;
        public AESRSAHybridWrapper()
        {
            this._platform = new OSPlatform();
            this._aesWrapper = new AESWrapper();
            this._rsaWrapper = new RSAWrapper();
        }

        public class AESRSAHybridEncryptResult()
        {
            public RsaKeyPairResult KeyPair { get; set; }
            public string CipherText { get; set; }
            public int AesType { get; set; }
            public string EncryptedAesKey { get; set; }
            public string NonceKey { get; set; }
        }

        public AESRSAHybridEncryptResult AES256RSAHybridEncrypt(string dataToEncrypt, string aesNonce, int rsaKeySize, int aesType)
        {
            if (string.IsNullOrEmpty(dataToEncrypt))
            {
                throw new Exception("Must provide data to encrypt with AES / RSA Hybrid");
            }
            if (string.IsNullOrEmpty(aesNonce))
            {
                throw new Exception("Must an AES Nonce to encrypt with AES / RSA Hybrid");
            }
            if (rsaKeySize != 1024 && rsaKeySize != 2048 && rsaKeySize != 4096)
            {
                throw new Exception("You must provide a valid key bit size to sign with RSA");
            }
            if (aesType != 128 && aesType != 256)
            {
                throw new Exception("You must provide an apporpriate AES Type");
            }
            RsaKeyPairResult rsaKeyPairResult = this._rsaWrapper.GetKeyPair(rsaKeySize);
            AesEncryptResult encryptResult = (aesType == 256) ? this._aesWrapper.Aes256Encrypt(aesNonce, dataToEncrypt) : this._aesWrapper.Aes128Encrypt(aesNonce, dataToEncrypt);
            string encryptedAesKey = this._rsaWrapper.RsaEncrypt(rsaKeyPairResult.PublicKey, encryptResult.Key);
            return new AESRSAHybridEncryptResult()
            {
                KeyPair = rsaKeyPairResult,
                CipherText = encryptResult.CipherText,
                EncryptedAesKey = encryptedAesKey,
                AesType = aesType,
                NonceKey = aesNonce,
            };
        }

        public string AES256RSAHybridDecrypt(AESRSAHybridEncryptResult encryptResult)
        {
            if (encryptResult.KeyPair?.PublicKey == null)
            {
                throw new Exception("You must provide a public key to decrypt with AES / RSA Hybrid");
            }
            if (encryptResult.KeyPair?.PrivateKey == null)
            {
                throw new Exception("You must provide a private key to decrypt with AES / RSA Hybrid");
            }
            if (encryptResult.CipherText == null)
            {
                throw new Exception("You must provide a ciphertext with AES / RSA Hybrid");
            }
            if (encryptResult.EncryptedAesKey == null)
            {
                throw new Exception("You must provide an encrypted AES Key to decrypt with AES / RSA Hybrid");
            }
            if (encryptResult.AesType != 128 && encryptResult.AesType != 256)
            {
                throw new Exception("You must provide an apporpriate AES Type");
            }
            if (encryptResult.NonceKey == null)
            {
                throw new Exception("You must provide an AES Nonce");
            }
            string decryptedAesKey = this._rsaWrapper.RsaDecrypt(encryptResult.KeyPair.PrivateKey, encryptResult.EncryptedAesKey);
            string decrypted = (encryptResult.AesType == 256) ? this._aesWrapper.Aes256Decrypt(encryptResult.NonceKey, decryptedAesKey, encryptResult.CipherText) : this._aesWrapper.DecryptAES128WithKey(encryptResult.NonceKey, decryptedAesKey, encryptResult.CipherText);
            return decrypted;
        }
    }
}
