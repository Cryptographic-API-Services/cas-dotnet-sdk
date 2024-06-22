using CasDotnetSdk.DigitalSignature.Linux;
using CasDotnetSdk.DigitalSignature.Types;
using CasDotnetSdk.DigitalSignature.Windows;
using CasDotnetSdk.Helpers;
using CasDotnetSdk.Http;
using CASHelpers;
using CASHelpers.Types.HttpResponses.BenchmarkAPI;
using System;
using System.Reflection;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.DigitalSignature
{
    public class SHA512DigitalSignatureWrapper : IDigitalSignature
    {
        private readonly OSPlatform _platform;
        private readonly BenchmarkSender _benchmarkSender;

        /// <summary>
        /// A wrapper class for creating Digital Signatures using SHA512 (ED25519-Dalek and RSA)
        /// </summary>
        public SHA512DigitalSignatureWrapper()
        {
            this._platform = new OperatingSystemDeterminator().GetOperatingSystem();
            this._benchmarkSender = new BenchmarkSender();
        }

        /// <summary>
        /// Creates an ED25519 Digital Signature using SHA512
        /// </summary>
        /// <param name="dataToSign"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public SHAED25519DalekDigitialSignatureResult CreateED25519(byte[] dataToSign)
        {
            if (dataToSign == null || dataToSign.Length == 0)
            {
                throw new Exception("You must provide an allocated data array to create a digital signature");
            }

            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                SHAED25519DalekStructDigitalSignatureResult signatureResult = DigitalSignatureLinuxWrapper.sha512_ed25519_digital_signature(dataToSign, dataToSign.Length);
                byte[] publicKey = new byte[signatureResult.public_key_length];
                Marshal.Copy(signatureResult.public_key, publicKey, 0, signatureResult.public_key_length);
                byte[] signature = new byte[signatureResult.signature_length];
                Marshal.Copy(signatureResult.signature_raw_ptr, signature, 0, signatureResult.signature_length);
                FreeMemoryHelper.FreeBytesMemory(signatureResult.public_key);
                FreeMemoryHelper.FreeBytesMemory(signatureResult.signature_raw_ptr);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.DigitalSignature, nameof(SHA512DigitalSignatureWrapper));
                return new SHAED25519DalekDigitialSignatureResult()
                {
                    PublicKey = publicKey,
                    Signature = signature,
                };
            }
            else
            {
                SHAED25519DalekStructDigitalSignatureResult signatureResult = DigitalSignatureWindowsWrapper.sha512_ed25519_digital_signature(dataToSign, dataToSign.Length);
                byte[] publicKey = new byte[signatureResult.public_key_length];
                Marshal.Copy(signatureResult.public_key, publicKey, 0, signatureResult.public_key_length);
                byte[] signature = new byte[signatureResult.signature_length];
                Marshal.Copy(signatureResult.signature_raw_ptr, signature, 0, signatureResult.signature_length);
                FreeMemoryHelper.FreeBytesMemory(signatureResult.public_key);
                FreeMemoryHelper.FreeBytesMemory(signatureResult.signature_raw_ptr);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.DigitalSignature, nameof(SHA512DigitalSignatureWrapper));
                return new SHAED25519DalekDigitialSignatureResult()
                {
                    PublicKey = publicKey,
                    Signature = signature,
                };
            }
        }

        /// <summary>
        /// Creates an ED25519 Digital Signature using SHA512 on the threadpool
        /// </summary>
        /// <param name="dataToSign"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public SHAED25519DalekDigitialSignatureResult CreateED25519Threadpool(byte[] dataToSign)
        {
            if (!CASConfiguration.IsThreadingEnabled)
            {
                throw new Exception("You do not have the product subscription to work with the thread pool featues");
            }

            if (dataToSign == null || dataToSign.Length == 0)
            {
                throw new Exception("You must provide an allocated data array to create a digital signature");
            }

            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                SHAED25519DalekStructDigitalSignatureResult signatureResult = DigitalSignatureLinuxWrapper.sha512_ed25519_digital_signature_threadpool(dataToSign, dataToSign.Length);
                byte[] publicKey = new byte[signatureResult.public_key_length];
                Marshal.Copy(signatureResult.public_key, publicKey, 0, signatureResult.public_key_length);
                byte[] signature = new byte[signatureResult.signature_length];
                Marshal.Copy(signatureResult.signature_raw_ptr, signature, 0, signatureResult.signature_length);
                FreeMemoryHelper.FreeBytesMemory(signatureResult.public_key);
                FreeMemoryHelper.FreeBytesMemory(signatureResult.signature_raw_ptr);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.DigitalSignature, nameof(SHA512DigitalSignatureWrapper));
                return new SHAED25519DalekDigitialSignatureResult()
                {
                    PublicKey = publicKey,
                    Signature = signature,
                };
            }
            else
            {
                SHAED25519DalekStructDigitalSignatureResult signatureResult = DigitalSignatureWindowsWrapper.sha512_ed25519_digital_signature_threadpool(dataToSign, dataToSign.Length);
                byte[] publicKey = new byte[signatureResult.public_key_length];
                Marshal.Copy(signatureResult.public_key, publicKey, 0, signatureResult.public_key_length);
                byte[] signature = new byte[signatureResult.signature_length];
                Marshal.Copy(signatureResult.signature_raw_ptr, signature, 0, signatureResult.signature_length);
                FreeMemoryHelper.FreeBytesMemory(signatureResult.public_key);
                FreeMemoryHelper.FreeBytesMemory(signatureResult.signature_raw_ptr);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.DigitalSignature, nameof(SHA512DigitalSignatureWrapper));
                return new SHAED25519DalekDigitialSignatureResult()
                {
                    PublicKey = publicKey,
                    Signature = signature,
                };
            }
        }

        /// <summary>
        /// Creates a RSA Digital Signature using SHA512
        /// </summary>
        /// <param name="rsaKeySize"></param>
        /// <param name="dataToSign"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public SHARSADigitalSignatureResult CreateRsa(int rsaKeySize, byte[] dataToSign)
        {
            if (rsaKeySize != 1024 && rsaKeySize != 2048 && rsaKeySize != 4096)
            {
                throw new Exception("Not a valid RSA key size");
            }
            if (dataToSign == null || dataToSign.Length == 0)
            {
                throw new Exception("Must provide an allocated data set to sign");
            }

            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                SHARSAStructDigitialSignatureResult result = DigitalSignatureLinuxWrapper.sha_512_rsa_digital_signature(rsaKeySize, dataToSign, dataToSign.Length);
                string publicKey = Marshal.PtrToStringAnsi(result.public_key);
                string privateKey = Marshal.PtrToStringAnsi(result.private_key);
                byte[] signature = new byte[result.length];
                Marshal.Copy(result.signature, signature, 0, result.length);
                FreeMemoryHelper.FreeCStringMemory(result.public_key);
                FreeMemoryHelper.FreeCStringMemory(result.private_key);
                FreeMemoryHelper.FreeBytesMemory(result.signature);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.DigitalSignature, nameof(SHA512DigitalSignatureWrapper));
                return new SHARSADigitalSignatureResult()
                {
                    PrivateKey = privateKey,
                    PublicKey = publicKey,
                    Signature = signature
                };
            }
            else
            {
                SHARSAStructDigitialSignatureResult result = DigitalSignatureWindowsWrapper.sha_512_rsa_digital_signature(rsaKeySize, dataToSign, dataToSign.Length);
                string publicKey = Marshal.PtrToStringAnsi(result.public_key);
                string privateKey = Marshal.PtrToStringAnsi(result.private_key);
                byte[] signature = new byte[result.length];
                Marshal.Copy(result.signature, signature, 0, result.length);
                FreeMemoryHelper.FreeCStringMemory(result.public_key);
                FreeMemoryHelper.FreeCStringMemory(result.private_key);
                FreeMemoryHelper.FreeBytesMemory(result.signature);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.DigitalSignature, nameof(SHA512DigitalSignatureWrapper));
                return new SHARSADigitalSignatureResult()
                {
                    PrivateKey = privateKey,
                    PublicKey = publicKey,
                    Signature = signature
                };
            }
        }

        /// <summary>
        /// Creates a RSA Digital Signature using SHA512 on the threadpool
        /// </summary>
        /// <param name="rsaKeySize"></param>
        /// <param name="dataToSign"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public SHARSADigitalSignatureResult CreateRsaThreadpool(int rsaKeySize, byte[] dataToSign)
        {
            if (!CASConfiguration.IsThreadingEnabled)
            {
                throw new Exception("You do not have the product subscription to work with the thread pool featues");
            }

            if (rsaKeySize != 1024 && rsaKeySize != 2048 && rsaKeySize != 4096)
            {
                throw new Exception("Not a valid RSA key size");
            }
            if (dataToSign == null || dataToSign.Length == 0)
            {
                throw new Exception("Must provide an allocated data set to sign");
            }

            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                SHARSAStructDigitialSignatureResult result = DigitalSignatureLinuxWrapper.sha_512_rsa_digital_signature_threadpool(rsaKeySize, dataToSign, dataToSign.Length);
                string publicKey = Marshal.PtrToStringAnsi(result.public_key);
                string privateKey = Marshal.PtrToStringAnsi(result.private_key);
                byte[] signature = new byte[result.length];
                Marshal.Copy(result.signature, signature, 0, result.length);
                FreeMemoryHelper.FreeCStringMemory(result.public_key);
                FreeMemoryHelper.FreeCStringMemory(result.private_key);
                FreeMemoryHelper.FreeBytesMemory(result.signature);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.DigitalSignature, nameof(SHA512DigitalSignatureWrapper));
                return new SHARSADigitalSignatureResult()
                {
                    PrivateKey = privateKey,
                    PublicKey = publicKey,
                    Signature = signature
                };
            }
            else
            {
                SHARSAStructDigitialSignatureResult result = DigitalSignatureWindowsWrapper.sha_512_rsa_digital_signature_threadpool(rsaKeySize, dataToSign, dataToSign.Length);
                string publicKey = Marshal.PtrToStringAnsi(result.public_key);
                string privateKey = Marshal.PtrToStringAnsi(result.private_key);
                byte[] signature = new byte[result.length];
                Marshal.Copy(result.signature, signature, 0, result.length);
                FreeMemoryHelper.FreeCStringMemory(result.public_key);
                FreeMemoryHelper.FreeCStringMemory(result.private_key);
                FreeMemoryHelper.FreeBytesMemory(result.signature);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.DigitalSignature, nameof(SHA512DigitalSignatureWrapper));
                return new SHARSADigitalSignatureResult()
                {
                    PrivateKey = privateKey,
                    PublicKey = publicKey,
                    Signature = signature
                };
            }
        }

        /// <summary>
        /// Verifies a ED25519 Digital Signature using SHA512
        /// </summary>
        /// <param name="publicKey"></param>
        /// <param name="dataToVerify"></param>
        /// <param name="signature"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public bool VerifyED25519(byte[] publicKey, byte[] dataToVerify, byte[] signature)
        {
            if (publicKey == null || publicKey.Length == 0)
            {
                throw new Exception("You must provide a allocated array for the public to verify a digital signature");
            }
            if (dataToVerify == null || dataToVerify.Length == 0)
            {
                throw new Exception("You must provde an allocated array for the data to verify to verify a digital signature");
            }
            if (signature == null || signature.Length == 0)
            {
                throw new Exception("You must provide an allocated array for the signature to verfiy a digital signature");
            }

            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                bool result = DigitalSignatureLinuxWrapper.sha512_ed25519_digital_signature_verify(publicKey, publicKey.Length, dataToVerify, dataToVerify.Length, signature, signature.Length);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.DigitalSignature, nameof(SHA512DigitalSignatureWrapper));
                return result;
            }
            else
            {
                bool result = DigitalSignatureWindowsWrapper.sha512_ed25519_digital_signature_verify(publicKey, publicKey.Length, dataToVerify, dataToVerify.Length, signature, signature.Length);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.DigitalSignature, nameof(SHA512DigitalSignatureWrapper));
                return result;
            }
        }

        /// <summary>
        /// Verifies a ED25519 Digital Signature using SHA512 on the threadpool
        /// </summary>
        /// <param name="publicKey"></param>
        /// <param name="dataToVerify"></param>
        /// <param name="signature"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public bool VerifyED25519Threadpool(byte[] publicKey, byte[] dataToVerify, byte[] signature)
        {
            if (!CASConfiguration.IsThreadingEnabled)
            {
                throw new Exception("You do not have the product subscription to work with the thread pool featues");
            }

            if (publicKey == null || publicKey.Length == 0)
            {
                throw new Exception("You must provide a allocated array for the public to verify a digital signature");
            }
            if (dataToVerify == null || dataToVerify.Length == 0)
            {
                throw new Exception("You must provde an allocated array for the data to verify to verify a digital signature");
            }
            if (signature == null || signature.Length == 0)
            {
                throw new Exception("You must provide an allocated array for the signature to verfiy a digital signature");
            }

            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                bool result = DigitalSignatureLinuxWrapper.sha512_ed25519_digital_signature_verify_threadpool(publicKey, publicKey.Length, dataToVerify, dataToVerify.Length, signature, signature.Length);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.DigitalSignature, nameof(SHA512DigitalSignatureWrapper));
                return result;
            }
            else
            {
                bool result = DigitalSignatureWindowsWrapper.sha512_ed25519_digital_signature_verify_threadpool(publicKey, publicKey.Length, dataToVerify, dataToVerify.Length, signature, signature.Length);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.DigitalSignature, nameof(SHA512DigitalSignatureWrapper));
                return result;
            }
        }

        /// <summary>
        /// Verifies a RSA Digital Signature using SHA512
        /// </summary>
        /// <param name="publicKey"></param>
        /// <param name="dataToVerify"></param>
        /// <param name="signature"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public bool VerifyRsa(string publicKey, byte[] dataToVerify, byte[] signature)
        {
            if (!RSAValidator.ValidateRsaPemKey(publicKey))
            {
                throw new Exception("You must provide a public key to verify with SHA512 RSA Digital Signature");
            }
            if (dataToVerify == null || dataToVerify.Length == 0)
            {
                throw new Exception("You must provide allocated data to verify");
            }
            if (signature == null || signature.Length == 0)
            {
                throw new Exception("You must provide a allocated signature to verify");
            }

            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                bool result = DigitalSignatureLinuxWrapper.sha_512_rsa_digital_signature_verify(publicKey, dataToVerify, dataToVerify.Length, signature, signature.Length);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.DigitalSignature, nameof(SHA512DigitalSignatureWrapper));
                return result;
            }
            else
            {
                bool result = DigitalSignatureWindowsWrapper.sha_512_rsa_digital_signature_verify(publicKey, dataToVerify, dataToVerify.Length, signature, signature.Length);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.DigitalSignature, nameof(SHA512DigitalSignatureWrapper));
                return result;
            }
        }

        /// <summary>
        /// Verifies a RSA Digital Signature using SHA512 on the threadpool
        /// </summary>
        /// <param name="publicKey"></param>
        /// <param name="dataToVerify"></param>
        /// <param name="signature"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public bool VerifyRsaThreadpool(string publicKey, byte[] dataToVerify, byte[] signature)
        {
            if (!CASConfiguration.IsThreadingEnabled)
            {
                throw new Exception("You do not have the product subscription to work with the thread pool featues");
            }

            if (!RSAValidator.ValidateRsaPemKey(publicKey))
            {
                throw new Exception("You must provide a public key to verify with SHA512 RSA Digital Signature");
            }
            if (dataToVerify == null || dataToVerify.Length == 0)
            {
                throw new Exception("You must provide allocated data to verify");
            }
            if (signature == null || signature.Length == 0)
            {
                throw new Exception("You must provide a allocated signature to verify");
            }

            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                bool result = DigitalSignatureLinuxWrapper.sha_512_rsa_digital_signature_verify_threadpool(publicKey, dataToVerify, dataToVerify.Length, signature, signature.Length);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.DigitalSignature, nameof(SHA512DigitalSignatureWrapper));
                return result;
            }
            else
            {
                bool result = DigitalSignatureWindowsWrapper.sha_512_rsa_digital_signature_verify_threadpool(publicKey, dataToVerify, dataToVerify.Length, signature, signature.Length);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.DigitalSignature, nameof(SHA512DigitalSignatureWrapper));
                return result;
            }
        }
    }
}
