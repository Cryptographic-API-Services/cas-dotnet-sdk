using CasDotnetSdk.Helpers;
using CasDotnetSdk.Hybrid.Types;
using CASHelpers.Types.HttpResponses.BenchmarkAPI;
using System.Reflection;
using System;
using System.Runtime.InteropServices;
using CasDotnetSdk.Hybrid.Windows;
using CasDotnetSdk.Hybrid.Linux;

namespace CasDotnetSdk.Hybrid
{
    public class HpkeWrapper : BaseWrapper
    {
        public HpkeWrapper()
        {

        }

        /// <summary>
        /// Generates a Private Key, Public Key, and InfoStr for usage with HPKE
        /// </summary>
        /// <returns></returns>
        public HpkeKeyPairResult GenerateKeyPair()
        {
            DateTime start = DateTime.UtcNow;
            HpkeKeyPairResultStruct keyPair = (this._platform == OSPlatform.Linux) ?
                HpkeLinuxWrapper.hpke_generate_keypair() :
                HpkeWindowsWrapper.hpke_generate_keypair();
            byte[] privateKeyResult = new byte[keyPair.private_key_ptr_length];
            byte[] publicKeyResult = new byte[keyPair.public_key_ptr_length];
            byte[] infoStrResult = new byte[keyPair.info_str_ptr_length];
            Marshal.Copy(keyPair.private_key_ptr, privateKeyResult, 0, keyPair.private_key_ptr_length);
            Marshal.Copy(keyPair.public_key_ptr, publicKeyResult, 0, keyPair.public_key_ptr_length);
            Marshal.Copy(keyPair.info_str_ptr, infoStrResult, 0, keyPair.info_str_ptr_length);
            FreeMemoryHelper.FreeBytesMemory(keyPair.public_key_ptr);
            FreeMemoryHelper.FreeBytesMemory(keyPair.private_key_ptr);
            FreeMemoryHelper.FreeBytesMemory(keyPair.info_str_ptr);
            HpkeKeyPairResult result = new HpkeKeyPairResult()
            {
                PrivateKey = privateKeyResult,
                PublicKey = publicKeyResult,
                InfoStr = infoStrResult
            };
            DateTime end = DateTime.UtcNow;
            this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(HpkeWrapper));
            return result;
        }

        public HpkeEncryptResult Encrypt(byte[] plaintText, byte[] publicKey, byte[] infoStr)
        {
            if (plaintText == null || plaintText.Length == 0)
            {
                throw new Exception("Must provide plaint text to encrypt with HPKE");
            }

            if (publicKey == null || publicKey.Length == 0)
            {
                throw new Exception("Must a public key to encrypt with HPKE");
            }

            if (infoStr == null || infoStr.Length == 0)
            {
                throw new Exception("Must a info str to encrypt with HPKE");
            }

            DateTime start = DateTime.UtcNow;
            HpkeEncryptResultStruct encrypt = (this._platform == OSPlatform.Linux) ?
                HpkeLinuxWrapper.hpke_encrypt(plaintText, plaintText.Length, publicKey, publicKey.Length, infoStr, infoStr.Length) :
                HpkeWindowsWrapper.hpke_encrypt(plaintText, plaintText.Length, publicKey, publicKey.Length, infoStr, infoStr.Length);
            byte[] encappedKeyResult = new byte[encrypt.encapped_key_ptr_length];
            byte[] cipherTextResult = new byte[encrypt.ciphertext_ptr_length];
            byte[] tagResult = new byte[encrypt.tag_ptr_length];
            Marshal.Copy(encrypt.encapped_key_ptr, encappedKeyResult, 0, encrypt.encapped_key_ptr_length);
            Marshal.Copy(encrypt.ciphertext_ptr, cipherTextResult, 0, encrypt.ciphertext_ptr_length);
            Marshal.Copy(encrypt.tag_ptr, tagResult, 0, encrypt.tag_ptr_length);
            FreeMemoryHelper.FreeBytesMemory(encrypt.ciphertext_ptr);
            FreeMemoryHelper.FreeBytesMemory(encrypt.encapped_key_ptr);
            FreeMemoryHelper.FreeBytesMemory(encrypt.tag_ptr);
            HpkeEncryptResult result = new HpkeEncryptResult()
            {
                Ciphertext = cipherTextResult,
                Tag = tagResult,
                EncappedKey = encappedKeyResult,
            };
            DateTime end = DateTime.UtcNow;
            this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(HpkeWrapper));
            return result;
        }

        public byte[] Decrypt(byte[] cipherText, byte[] privateKey, byte[] encappedKey, byte[] tag, byte[] infoStr)
        {
            if (cipherText == null || cipherText.Length == 0)
            {
                throw new Exception("Must provide ciphertext to decrypt with HPKE");
            }

            if (privateKey == null || privateKey.Length == 0)
            {
                throw new Exception("Must a private key to decrypt with HPKE");
            }

            if (encappedKey == null || encappedKey.Length == 0)
            {
                throw new Exception("Must provide an encapped key to decrypt with HPKE");
            }

            if (tag == null || tag.Length == 0)
            {
                throw new Exception("Must provide a tag to decrypt with HPKE");
            }

            if (infoStr == null || infoStr.Length == 0)
            {
                throw new Exception("Must a info str to decrypt with HPKE");
            }

            DateTime start = DateTime.UtcNow;
            HpkeDecryptResultStruct decrypt = (this._platform == OSPlatform.Linux) ?
                HpkeLinuxWrapper.hpke_decrypt(cipherText, cipherText.Length, privateKey, privateKey.Length, encappedKey, encappedKey.Length, tag, tag.Length, infoStr, infoStr.Length) :
                HpkeWindowsWrapper.hpke_decrypt(cipherText, cipherText.Length, privateKey, privateKey.Length, encappedKey, encappedKey.Length, tag, tag.Length, infoStr, infoStr.Length);
            byte[] result = new byte[decrypt.plaintext_ptr_length];
            Marshal.Copy(decrypt.plaintext_ptr, result, 0, decrypt.plaintext_ptr_length);
            FreeMemoryHelper.FreeBytesMemory(decrypt.plaintext_ptr);
            DateTime end = DateTime.UtcNow;
            this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(HpkeWrapper));
            return result;
        }
    }
}
