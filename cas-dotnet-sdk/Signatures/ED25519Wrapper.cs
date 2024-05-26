using CasDotnetSdk.Http;
using CasDotnetSdk.Signatures.Linux;
using CasDotnetSdk.Signatures.Types;
using CasDotnetSdk.Signatures.Windows;
using CASHelpers;
using CASHelpers.Types.HttpResponses.BenchmarkAPI;
using System;
using System.Reflection;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Signatures
{
    public class ED25519Wrapper
    {
        private readonly OSPlatform _platform;
        private readonly BenchmarkSender _benchmarkSender;

        public ED25519Wrapper()
        {
            this._platform = new OperatingSystemDeterminator().GetOperatingSystem();
            this._benchmarkSender = new BenchmarkSender();
        }

        /// <summary>
        /// Generates and public and private key pair non split in bytes for ED25519-Dalek.
        /// </summary>
        /// <returns></returns>
        public byte[] GetKeyPairBytes()
        {
            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                Ed25519KeyPairBytesResultStruct resultStruct = ED25519LinuxWrapper.get_ed25519_key_pair_bytes();
                byte[] keyPairResult = new byte[resultStruct.length];
                Marshal.Copy(resultStruct.key_pair, keyPairResult, 0, resultStruct.length);
                ED25519LinuxWrapper.free_bytes(resultStruct.key_pair);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(ED25519Wrapper));
                return keyPairResult;
            }
            else
            {
                Ed25519KeyPairBytesResultStruct resultStruct = ED25519WindowsWrapper.get_ed25519_key_pair_bytes();
                byte[] keyPairResult = new byte[resultStruct.length];
                Marshal.Copy(resultStruct.key_pair, keyPairResult, 0, resultStruct.length);
                ED25519WindowsWrapper.free_bytes(resultStruct.key_pair);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(ED25519Wrapper));
                return keyPairResult;
            }
        }

        /// <summary>
        /// Generates and public and private key pair non split in bytes for ED25519-Dalek on the threadpool.
        /// </summary>
        /// <returns></returns>
        public byte[] GetKeyPairBytesThreadpool()
        {
            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                Ed25519KeyPairBytesResultStruct resultStruct = ED25519LinuxWrapper.get_ed25519_key_pair_bytes_threadpool();
                byte[] keyPairResult = new byte[resultStruct.length];
                Marshal.Copy(resultStruct.key_pair, keyPairResult, 0, resultStruct.length);
                ED25519LinuxWrapper.free_bytes(resultStruct.key_pair);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(ED25519Wrapper));
                return keyPairResult;
            }
            else
            {
                Ed25519KeyPairBytesResultStruct resultStruct = ED25519WindowsWrapper.get_ed25519_key_pair_bytes_threadpool();
                byte[] keyPairResult = new byte[resultStruct.length];
                Marshal.Copy(resultStruct.key_pair, keyPairResult, 0, resultStruct.length);
                ED25519WindowsWrapper.free_bytes(resultStruct.key_pair);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(ED25519Wrapper));
                return keyPairResult;
            }
        }

        /// <summary>
        /// Signs data with a key pair in bytes for ED25519-Dalek.
        /// </summary>
        /// <param name="keyBytes"></param>
        /// <param name="dataToSign"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public Ed25519ByteSignatureResult SignBytes(byte[] keyBytes, byte[] dataToSign)
        {
            if (keyBytes == null || keyBytes.Length == 0)
            {
                throw new Exception("You must provide an array allocated with key data to Sign with ED25519-Dalek");
            }
            if (dataToSign == null || dataToSign.Length == 0)
            {
                throw new Exception("You must provide an array allocated with data to Sign with ED25519-Dalek");
            }

            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                Ed25519ByteSignatureResultStruct resultStruct = ED25519LinuxWrapper.sign_with_key_pair_bytes(keyBytes, keyBytes.Length, dataToSign, dataToSign.Length);
                byte[] publicKeyResult = new byte[resultStruct.public_key_length];
                Marshal.Copy(resultStruct.public_key, publicKeyResult, 0, resultStruct.public_key_length);
                ED25519LinuxWrapper.free_bytes(resultStruct.public_key);
                byte[] signatureResult = new byte[resultStruct.signature_length];
                Marshal.Copy(resultStruct.signature_byte_ptr, signatureResult, 0, resultStruct.signature_length);
                ED25519LinuxWrapper.free_bytes(resultStruct.signature_byte_ptr);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(ED25519Wrapper));
                return new Ed25519ByteSignatureResult()
                {
                    PublicKey = publicKeyResult,
                    Signature = signatureResult
                };
            }
            else
            {
                Ed25519ByteSignatureResultStruct resultStruct = ED25519WindowsWrapper.sign_with_key_pair_bytes(keyBytes, keyBytes.Length, dataToSign, dataToSign.Length);
                byte[] publicKeyResult = new byte[resultStruct.public_key_length];
                Marshal.Copy(resultStruct.public_key, publicKeyResult, 0, resultStruct.public_key_length);
                ED25519WindowsWrapper.free_bytes(resultStruct.public_key);
                byte[] signatureResult = new byte[resultStruct.signature_length];
                Marshal.Copy(resultStruct.signature_byte_ptr, signatureResult, 0, resultStruct.signature_length);
                ED25519WindowsWrapper.free_bytes(resultStruct.signature_byte_ptr);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(ED25519Wrapper));
                return new Ed25519ByteSignatureResult()
                {
                    PublicKey = publicKeyResult,
                    Signature = signatureResult
                };
            }
        }

        /// <summary>
        /// Signs data with a key pair in bytes for ED25519-Dalek on the threadpool.
        /// </summary>
        /// <param name="keyBytes"></param>
        /// <param name="dataToSign"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public Ed25519ByteSignatureResult SignBytesThreadpool(byte[] keyBytes, byte[] dataToSign)
        {
            if (keyBytes == null || keyBytes.Length == 0)
            {
                throw new Exception("You must provide an array allocated with key data to Sign with ED25519-Dalek");
            }
            if (dataToSign == null || dataToSign.Length == 0)
            {
                throw new Exception("You must provide an array allocated with data to Sign with ED25519-Dalek");
            }

            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                Ed25519ByteSignatureResultStruct resultStruct = ED25519LinuxWrapper.sign_with_key_pair_bytes_threadpool(keyBytes, keyBytes.Length, dataToSign, dataToSign.Length);
                byte[] publicKeyResult = new byte[resultStruct.public_key_length];
                Marshal.Copy(resultStruct.public_key, publicKeyResult, 0, resultStruct.public_key_length);
                ED25519LinuxWrapper.free_bytes(resultStruct.public_key);
                byte[] signatureResult = new byte[resultStruct.signature_length];
                Marshal.Copy(resultStruct.signature_byte_ptr, signatureResult, 0, resultStruct.signature_length);
                ED25519LinuxWrapper.free_bytes(resultStruct.signature_byte_ptr);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(ED25519Wrapper));
                return new Ed25519ByteSignatureResult()
                {
                    PublicKey = publicKeyResult,
                    Signature = signatureResult
                };
            }
            else
            {
                Ed25519ByteSignatureResultStruct resultStruct = ED25519WindowsWrapper.sign_with_key_pair_bytes_threadpool(keyBytes, keyBytes.Length, dataToSign, dataToSign.Length);
                byte[] publicKeyResult = new byte[resultStruct.public_key_length];
                Marshal.Copy(resultStruct.public_key, publicKeyResult, 0, resultStruct.public_key_length);
                ED25519WindowsWrapper.free_bytes(resultStruct.public_key);
                byte[] signatureResult = new byte[resultStruct.signature_length];
                Marshal.Copy(resultStruct.signature_byte_ptr, signatureResult, 0, resultStruct.signature_length);
                ED25519WindowsWrapper.free_bytes(resultStruct.signature_byte_ptr);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(ED25519Wrapper));
                return new Ed25519ByteSignatureResult()
                {
                    PublicKey = publicKeyResult,
                    Signature = signatureResult
                };
            }
        }

        /// <summary>
        /// Verifys data with a key pair in bytes for ED25519-Dalek.
        /// </summary>
        /// <param name="keyPair"></param>
        /// <param name="signature"></param>
        /// <param name="dataToVerify"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public bool VerifyBytes(byte[] keyPair, byte[] signature, byte[] dataToVerify)
        {
            if (keyPair?.Length == 0)
            {
                throw new Exception("You must provide allocated key pair data to Verify Bytes with ED25519-Dalek");
            }
            if (signature?.Length == 0)
            {
                throw new Exception("You must provide allocated signature data to Verify Bytes with ED25519-Dalek");
            }
            if (dataToVerify?.Length == 0)
            {
                throw new Exception("You must provide allocated data to Verify with ED25519-Dalek");
            }

            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                bool result = ED25519LinuxWrapper.verify_with_key_pair_bytes(keyPair, keyPair.Length, signature, signature.Length, dataToVerify, dataToVerify.Length);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(ED25519Wrapper));
                return result;
            }
            else
            {
                bool result = ED25519WindowsWrapper.verify_with_key_pair_bytes(keyPair, keyPair.Length, signature, signature.Length, dataToVerify, dataToVerify.Length);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(ED25519Wrapper));
                return result;
            }
        }

        /// <summary>
        /// Verifys data with a key pair in bytes for ED25519-Dalek on the threadpool.
        /// </summary>
        /// <param name="keyPair"></param>
        /// <param name="signature"></param>
        /// <param name="dataToVerify"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public bool VerifyBytesThreadpool(byte[] keyPair, byte[] signature, byte[] dataToVerify)
        {
            if (keyPair?.Length == 0)
            {
                throw new Exception("You must provide allocated key pair data to Verify Bytes with ED25519-Dalek");
            }
            if (signature?.Length == 0)
            {
                throw new Exception("You must provide allocated signature data to Verify Bytes with ED25519-Dalek");
            }
            if (dataToVerify?.Length == 0)
            {
                throw new Exception("You must provide allocated data to Verify with ED25519-Dalek");
            }

            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                bool result = ED25519LinuxWrapper.verify_with_key_pair_bytes_threadpool(keyPair, keyPair.Length, signature, signature.Length, dataToVerify, dataToVerify.Length);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(ED25519Wrapper));
                return result;
            }
            else
            {
                bool result = ED25519WindowsWrapper.verify_with_key_pair_bytes_threadpool(keyPair, keyPair.Length, signature, signature.Length, dataToVerify, dataToVerify.Length);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(ED25519Wrapper));
                return result;
            }
        }

        /// <summary>
        /// Verifies with a public key in bytes for ED25519-Dalek.
        /// </summary>
        /// <param name="publicKey"></param>
        /// <param name="signature"></param>
        /// <param name="dataToVerify"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>

        public bool VerifyWithPublicKeyBytes(byte[] publicKey, byte[] signature, byte[] dataToVerify)
        {
            if (publicKey?.Length == 0)
            {
                throw new Exception("You must provide allocated data for the public key to verify with ED25519-Dalek");
            }
            if (signature?.Length == 0)
            {
                throw new Exception("You must provide allocated data for the signature to verify with ED25519-Dalek");
            }
            if (dataToVerify?.Length == 0)
            {
                throw new Exception("You must provide allocated data to verify for the signature to verify with ED25519-Dalek");
            }
            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                bool result = ED25519LinuxWrapper.verify_with_public_key_bytes(publicKey, publicKey.Length, signature, signature.Length, dataToVerify, dataToVerify.Length);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(ED25519Wrapper));
                return result;
            }
            else
            {
                bool result = ED25519WindowsWrapper.verify_with_public_key_bytes(publicKey, publicKey.Length, signature, signature.Length, dataToVerify, dataToVerify.Length);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(ED25519Wrapper));
                return result;
            }
        }

        /// <summary>
        /// Verifies with a public key in bytes for ED25519-Dalek on the threadpool.
        /// </summary>
        /// <param name="publicKey"></param>
        /// <param name="signature"></param>
        /// <param name="dataToVerify"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>

        public bool VerifyWithPublicKeyBytesThreadpool(byte[] publicKey, byte[] signature, byte[] dataToVerify)
        {
            if (publicKey?.Length == 0)
            {
                throw new Exception("You must provide allocated data for the public key to verify with ED25519-Dalek");
            }
            if (signature?.Length == 0)
            {
                throw new Exception("You must provide allocated data for the signature to verify with ED25519-Dalek");
            }
            if (dataToVerify?.Length == 0)
            {
                throw new Exception("You must provide allocated data to verify for the signature to verify with ED25519-Dalek");
            }
            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                bool result = ED25519LinuxWrapper.verify_with_public_key_bytes_threadpool(publicKey, publicKey.Length, signature, signature.Length, dataToVerify, dataToVerify.Length);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(ED25519Wrapper));
                return result;
            }
            else
            {
                bool result = ED25519WindowsWrapper.verify_with_public_key_bytes_threadpool(publicKey, publicKey.Length, signature, signature.Length, dataToVerify, dataToVerify.Length);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(ED25519Wrapper));
                return result;
            }
        }
    }
}