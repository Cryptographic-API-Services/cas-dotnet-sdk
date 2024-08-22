using CasDotnetSdk.Asymmetric.Linux;
using CasDotnetSdk.Asymmetric.Types;
using CasDotnetSdk.Asymmetric.Windows;
using CasDotnetSdk.Helpers;
using CASHelpers;
using CASHelpers.Types.HttpResponses.BenchmarkAPI;
using System;
using System.Reflection;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Asymmetric
{
    public class RSAWrapper : BaseWrapper
    {
        /// <summary>
        /// A wrapper class for RSA key creation, encryption, decryption, signing, and verification.
        /// </summary>
        public RSAWrapper()
        {
            
        }

        /// <summary>
        /// Signs data with an RSA private key.
        /// </summary>
        /// <param name="privateKey"></param>
        /// <param name="dataToSign"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public byte[] RsaSignWithKeyBytes(string privateKey, byte[] dataToSign)
        {
            if (!RSAValidator.ValidateRsaPemKey(privateKey))
            {
                throw new Exception("You must provide a private key to sign with RSA");
            }
            if (dataToSign == null || dataToSign.Length == 0)
            {
                throw new Exception("You must provide allocated data to sign with RSA");
            }

            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                RsaSignBytesResults signResult = RSALinuxWrapper.rsa_sign_with_key_bytes(privateKey, dataToSign, dataToSign.Length);
                byte[] result = new byte[signResult.length];
                Marshal.Copy(signResult.signature_raw_ptr, result, 0, signResult.length);
                FreeMemoryHelper.FreeBytesMemory(signResult.signature_raw_ptr);
                DateTime end = DateTime.UtcNow;
                this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Asymmetric, nameof(RSAWrapper));
                return result;
            }
            else
            {
                RsaSignBytesResults signResult = RSAWindowsWrapper.rsa_sign_with_key_bytes(privateKey, dataToSign, dataToSign.Length);
                byte[] result = new byte[signResult.length];
                Marshal.Copy(signResult.signature_raw_ptr, result, 0, signResult.length);
                FreeMemoryHelper.FreeBytesMemory(signResult.signature_raw_ptr);
                DateTime end = DateTime.UtcNow;
                this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Asymmetric, nameof(RSAWrapper));
                return result;
            }
        }

        /// <summary>
        /// Signs data with an RSA private key on the threadpool.
        /// </summary>
        /// <param name="privateKey"></param>
        /// <param name="dataToSign"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public byte[] RsaSignWithKeyBytesThreadpool(string privateKey, byte[] dataToSign)
        {
            if (!CASConfiguration.IsThreadingEnabled)
            {
                throw new Exception("You do not have the product subscription to work with the thread pool featues");
            }

            if (!RSAValidator.ValidateRsaPemKey(privateKey))
            {
                throw new Exception("You must provide a private key to sign with RSA");
            }
            if (dataToSign == null || dataToSign.Length == 0)
            {
                throw new Exception("You must provide allocated data to sign with RSA");
            }

            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                RsaSignBytesResults signResult = RSALinuxWrapper.rsa_sign_with_key_bytes_threadpool(privateKey, dataToSign, dataToSign.Length);
                byte[] result = new byte[signResult.length];
                Marshal.Copy(signResult.signature_raw_ptr, result, 0, signResult.length);
                FreeMemoryHelper.FreeBytesMemory(signResult.signature_raw_ptr);
                DateTime end = DateTime.UtcNow;
                this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Asymmetric, nameof(RSAWrapper));
                return result;
            }
            else
            {
                RsaSignBytesResults signResult = RSAWindowsWrapper.rsa_sign_with_key_bytes_threadpool(privateKey, dataToSign, dataToSign.Length);
                byte[] result = new byte[signResult.length];
                Marshal.Copy(signResult.signature_raw_ptr, result, 0, signResult.length);
                FreeMemoryHelper.FreeBytesMemory(signResult.signature_raw_ptr);
                DateTime end = DateTime.UtcNow;
                this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Asymmetric, nameof(RSAWrapper));
                return result;
            }
        }


        /// <summary>
        /// Verifies data with an RSA public key.
        /// </summary>
        /// <param name="publicKey"></param>
        /// <param name="dataToVerify"></param>
        /// <param name="signature"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public bool RsaVerifyBytes(string publicKey, byte[] dataToVerify, byte[] signature)
        {
            if (!RSAValidator.ValidateRsaPemKey(publicKey))
            {
                throw new Exception("You must provide a public key to verify with RSA");
            }
            if (dataToVerify == null || dataToVerify.Length == 0)
            {
                throw new Exception("You must provide allocated data to verify with RSA");
            }
            if (signature == null || signature.Length == 0)
            {
                throw new Exception("You must provide an allocated signature to verify with RSA");
            }
            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {

                bool result = RSALinuxWrapper.rsa_verify_bytes(publicKey, dataToVerify, dataToVerify.Length, signature, signature.Length);
                DateTime end = DateTime.UtcNow;
                this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Asymmetric, nameof(RSAWrapper));
                return result;
            }
            else
            {
                bool result = RSAWindowsWrapper.rsa_verify_bytes(publicKey, dataToVerify, dataToVerify.Length, signature, signature.Length);
                DateTime end = DateTime.UtcNow;
                this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Asymmetric, nameof(RSAWrapper));
                return result;
            }
        }

        /// Verifies data with an RSA public key on the threadpool.
        /// </summary>
        /// <param name="publicKey"></param>
        /// <param name="dataToVerify"></param>
        /// <param name="signature"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public bool RsaVerifyBytesThreadpool(string publicKey, byte[] dataToVerify, byte[] signature)
        {
            if (!CASConfiguration.IsThreadingEnabled)
            {
                throw new Exception("You do not have the product subscription to work with the thread pool featues");
            }

            if (!RSAValidator.ValidateRsaPemKey(publicKey))
            {
                throw new Exception("You must provide a public key to verify with RSA");
            }
            if (dataToVerify == null || dataToVerify.Length == 0)
            {
                throw new Exception("You must provide allocated data to verify with RSA");
            }
            if (signature == null || signature.Length == 0)
            {
                throw new Exception("You must provide an allocated signature to verify with RSA");
            }
            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {

                bool result = RSALinuxWrapper.rsa_verify_bytes_threadpool(publicKey, dataToVerify, dataToVerify.Length, signature, signature.Length);
                DateTime end = DateTime.UtcNow;
                this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Asymmetric, nameof(RSAWrapper));
                return result;
            }
            else
            {
                bool result = RSAWindowsWrapper.rsa_verify_bytes_threadpool(publicKey, dataToVerify, dataToVerify.Length, signature, signature.Length);
                DateTime end = DateTime.UtcNow;
                this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Asymmetric, nameof(RSAWrapper));
                return result;
            }
        }

        /// <summary>
        /// Generates an RSA key based on the key size provided. (1024, 2048, 4096)
        /// </summary>
        /// <param name="keySize"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public RsaKeyPairResult GetKeyPair(int keySize)
        {
            if (keySize != 1024 && keySize != 2048 && keySize != 4096)
            {
                throw new Exception("Please pass in a valid key size.");
            }

            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                RsaKeyPairStruct keyPairStruct = RSALinuxWrapper.get_key_pair(keySize);
                RsaKeyPairResult result = new RsaKeyPairResult()
                {
                    PrivateKey = Marshal.PtrToStringAnsi(keyPairStruct.priv_key),
                    PublicKey = Marshal.PtrToStringAnsi(keyPairStruct.pub_key)
                };
                FreeMemoryHelper.FreeCStringMemory(keyPairStruct.pub_key);
                FreeMemoryHelper.FreeCStringMemory(keyPairStruct.priv_key);
                DateTime end = DateTime.UtcNow;
                this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Asymmetric, nameof(RSAWrapper));
                return result;
            }
            else
            {
                RsaKeyPairStruct keyPairStruct = RSAWindowsWrapper.get_key_pair(keySize);
                RsaKeyPairResult result = new RsaKeyPairResult()
                {
                    PrivateKey = Marshal.PtrToStringAnsi(keyPairStruct.priv_key),
                    PublicKey = Marshal.PtrToStringAnsi(keyPairStruct.pub_key)
                };
                FreeMemoryHelper.FreeCStringMemory(keyPairStruct.pub_key);
                FreeMemoryHelper.FreeCStringMemory(keyPairStruct.priv_key);
                DateTime end = DateTime.UtcNow;
                this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Asymmetric, nameof(RSAWrapper));
                return result;
            }
        }

        /// <summary>
        /// Generates an RSA key based on the key size provided. (1024, 2048, 4096) on the thread pool.
        /// </summary>
        /// <param name="keySize"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public RsaKeyPairResult GetKeyPairThreadPool(int keySize)
        {
            if (!CASConfiguration.IsThreadingEnabled)
            {
                throw new Exception("You do not have the product subscription to work with the thread pool featues");
            }

            if (keySize != 1024 && keySize != 2048 && keySize != 4096)
            {
                throw new Exception("Please pass in a valid key size.");
            }

            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                RsaKeyPairStruct keyPairStruct = RSALinuxWrapper.get_key_pair_threadpool(keySize);
                RsaKeyPairResult result = new RsaKeyPairResult()
                {
                    PrivateKey = Marshal.PtrToStringAnsi(keyPairStruct.priv_key),
                    PublicKey = Marshal.PtrToStringAnsi(keyPairStruct.pub_key)
                };
                FreeMemoryHelper.FreeCStringMemory(keyPairStruct.pub_key);
                FreeMemoryHelper.FreeCStringMemory(keyPairStruct.priv_key);
                DateTime end = DateTime.UtcNow;
                this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Asymmetric, nameof(RSAWrapper));
                return result;
            }
            else
            {
                RsaKeyPairStruct keyPairStruct = RSAWindowsWrapper.get_key_pair_threadpool(keySize);
                RsaKeyPairResult result = new RsaKeyPairResult()
                {
                    PrivateKey = Marshal.PtrToStringAnsi(keyPairStruct.priv_key),
                    PublicKey = Marshal.PtrToStringAnsi(keyPairStruct.pub_key)
                };
                FreeMemoryHelper.FreeCStringMemory(keyPairStruct.pub_key);
                FreeMemoryHelper.FreeCStringMemory(keyPairStruct.priv_key);
                DateTime end = DateTime.UtcNow;
                this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Asymmetric, nameof(RSAWrapper));
                return result;
            }
        }
    }
}
