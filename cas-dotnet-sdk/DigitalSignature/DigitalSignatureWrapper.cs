using CasDotnetSdk.DigitalSignature.Linux;
using CasDotnetSdk.DigitalSignature.Types;
using CasDotnetSdk.DigitalSignature.Windows;
using CasDotnetSdk.Http;
using CASHelpers;
using CASHelpers.Types.HttpResponses.BenchmarkAPI;
using System;
using System.Reflection;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.DigitalSignature
{
    public class DigitalSignatureWrapper
    {
        private readonly OSPlatform _platform;
        private readonly BenchmarkSender _benchmarkSender;
        public DigitalSignatureWrapper()
        {
            this._platform = new OperatingSystemDeterminator().GetOperatingSystem();
            this._benchmarkSender = new BenchmarkSender();
        }

        public SHARSADigitalSignatureResult SHA512RSADigitalSignature(int rsaKeySize, byte[] dataToSign)
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
                DigitalSignatureLinuxWrapper.free_cstring(result.public_key);
                DigitalSignatureLinuxWrapper.free_cstring(result.private_key);
                DigitalSignatureLinuxWrapper.free_bytes(result.signature);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.DigitalSignature, nameof(DigitalSignatureWrapper));
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
                DigitalSignatureWindowsWrapper.free_cstring(result.public_key);
                DigitalSignatureWindowsWrapper.free_cstring(result.private_key);
                DigitalSignatureWindowsWrapper.free_bytes(result.signature);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.DigitalSignature, nameof(DigitalSignatureWrapper));
                return new SHARSADigitalSignatureResult()
                {
                    PrivateKey = privateKey,
                    PublicKey = publicKey,
                    Signature = signature
                };
            }
        }

        public bool SHA512RSADigitalSignatureVerify(string publicKey, byte[] dataToVerify, byte[] signature)
        {
            if (string.IsNullOrEmpty(publicKey))
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
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.DigitalSignature, nameof(DigitalSignatureWrapper));
                return result;
            }
            else
            {
                bool result = DigitalSignatureWindowsWrapper.sha_512_rsa_digital_signature_verify(publicKey, dataToVerify, dataToVerify.Length, signature, signature.Length);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.DigitalSignature, nameof(DigitalSignatureWrapper));
                return result;
            }
        }

        public SHAED25519DalekDigitialSignatureResult SHA512ED25519DigitalSignature(byte[] dataToSign)
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
                DigitalSignatureLinuxWrapper.free_bytes(signatureResult.public_key);
                DigitalSignatureLinuxWrapper.free_bytes(signatureResult.signature_raw_ptr);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.DigitalSignature, nameof(DigitalSignatureWrapper));
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
                DigitalSignatureWindowsWrapper.free_bytes(signatureResult.public_key);
                DigitalSignatureWindowsWrapper.free_bytes(signatureResult.signature_raw_ptr);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.DigitalSignature, nameof(DigitalSignatureWrapper));
                return new SHAED25519DalekDigitialSignatureResult()
                {
                    PublicKey = publicKey,
                    Signature = signature,
                };
            }
        }

        public bool SHA512ED25519DigitalSignatureVerify(byte[] publicKey, byte[] dataToVerify, byte[] signature)
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
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.DigitalSignature, nameof(DigitalSignatureWrapper));
                return result;
            }
            else
            {
                bool result = DigitalSignatureWindowsWrapper.sha512_ed25519_digital_signature_verify(publicKey, publicKey.Length, dataToVerify, dataToVerify.Length, signature, signature.Length);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.DigitalSignature, nameof(DigitalSignatureWrapper));
                return result;
            }
        }

        public SHARSADigitalSignatureResult SHA256RSADigitalSignature(int rsaKeySize, byte[] dataToSign)
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
                DateTime end = DateTime.UtcNow;
                SHARSAStructDigitialSignatureResult result = DigitalSignatureLinuxWrapper.sha_256_rsa_digital_signature(rsaKeySize, dataToSign, dataToSign.Length);
                byte[] signature = new byte[result.length];
                Marshal.Copy(result.signature, signature, 0, signature.Length);
                string publicKey = Marshal.PtrToStringAnsi(result.public_key);
                string privateKey = Marshal.PtrToStringAnsi(result.private_key);
                SHARSADigitalSignatureResult resultToReturn = new SHARSADigitalSignatureResult()
                {
                    Signature = signature,
                    PrivateKey = privateKey,
                    PublicKey = publicKey
                };
                DigitalSignatureLinuxWrapper.free_bytes(result.signature);
                DigitalSignatureLinuxWrapper.free_cstring(result.public_key);
                DigitalSignatureLinuxWrapper.free_cstring(result.private_key);
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.DigitalSignature, nameof(DigitalSignatureWrapper));
                return resultToReturn;
            }
            else
            {
                DateTime end = DateTime.UtcNow;
                SHARSAStructDigitialSignatureResult result = DigitalSignatureWindowsWrapper.sha_256_rsa_digital_signature(rsaKeySize, dataToSign, dataToSign.Length);
                byte[] signature = new byte[result.length];
                Marshal.Copy(result.signature, signature, 0, signature.Length);
                string publicKey = Marshal.PtrToStringAnsi(result.public_key);
                string privateKey = Marshal.PtrToStringAnsi(result.private_key);
                SHARSADigitalSignatureResult resultToReturn = new SHARSADigitalSignatureResult()
                {
                    Signature = signature,
                    PrivateKey = privateKey,
                    PublicKey = publicKey
                };
                DigitalSignatureWindowsWrapper.free_bytes(result.signature);
                DigitalSignatureWindowsWrapper.free_cstring(result.public_key);
                DigitalSignatureWindowsWrapper.free_cstring(result.private_key);
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.DigitalSignature, nameof(DigitalSignatureWrapper));
                return resultToReturn;
            }
        }

        public bool SHA256RSADigitalSignatureVerify(string publicKey, byte[] dataToVerify, byte[] signature)
        {
            if (string.IsNullOrEmpty(publicKey))
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
                bool result = DigitalSignatureLinuxWrapper.sha_256_rsa_digital_signature_verify(publicKey, dataToVerify, dataToVerify.Length, signature, signature.Length);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.DigitalSignature, nameof(DigitalSignatureWrapper));
                return result;
            }
            else
            {
                bool result = DigitalSignatureWindowsWrapper.sha_256_rsa_digital_signature_verify(publicKey, dataToVerify, dataToVerify.Length, signature, signature.Length);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.DigitalSignature, nameof(DigitalSignatureWrapper));
                return result;
            }
        }
    }
}