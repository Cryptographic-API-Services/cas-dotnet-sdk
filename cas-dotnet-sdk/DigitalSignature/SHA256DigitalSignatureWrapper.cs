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
    public class SHA256DigitalSignatureWrapper : IDigitalSignature
    {
        private readonly OSPlatform _platform;
        private readonly BenchmarkSender _benchmarkSender;
        public SHA256DigitalSignatureWrapper()
        {
            this._platform = new OperatingSystemDeterminator().GetOperatingSystem();
            this._benchmarkSender = new BenchmarkSender();
        }

        public SHAED25519DalekDigitialSignatureResult CreateED25519(byte[] dataToSign)
        {
            throw new NotImplementedException();
        }

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
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.DigitalSignature, nameof(SHA256DigitalSignatureWrapper));
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
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.DigitalSignature, nameof(SHA256DigitalSignatureWrapper));
                return resultToReturn;
            }
        }

        public bool VerifyED25519(byte[] publicKey, byte[] dataToVerify, byte[] signature)
        {
            throw new NotImplementedException();
        }

        public bool VerifyRsa(string publicKey, byte[] dataToVerify, byte[] signature)
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
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.DigitalSignature, nameof(SHA256DigitalSignatureWrapper));
                return result;
            }
            else
            {
                bool result = DigitalSignatureWindowsWrapper.sha_256_rsa_digital_signature_verify(publicKey, dataToVerify, dataToVerify.Length, signature, signature.Length);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.DigitalSignature, nameof(SHA256DigitalSignatureWrapper));
                return result;
            }
        }
    }
}
