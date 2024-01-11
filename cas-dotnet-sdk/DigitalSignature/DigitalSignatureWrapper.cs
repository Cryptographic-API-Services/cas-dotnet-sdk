using CasDotnetSdk.DigitalSignature.Linux;
using CasDotnetSdk.DigitalSignature.Windows;
using CasDotnetSdk.Http;
using CasDotnetSdk.Symmetric;
using CASHelpers;
using CASHelpers.Types.HttpResponses.BenchmarkAPI;
using System;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

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

        public class SHARSADigitalSignatureResult
        {
            public string PublicKey { get; set; }
            public string PrivateKey { get; set; }
            public byte[] Signature { get; set; }
        }

        public struct SHARSADigitialSignatureResult
        {
            public IntPtr private_key { get; set; }
            public IntPtr public_key { get; set; }
            public IntPtr signature { get; set; }
            public int length { get; set; }
        }

        public struct SHAED25519DalekDigitalSignatureResult
        {
            public IntPtr public_key { get; set; }
            public int public_key_length { get; set; }
            public IntPtr signature_raw_ptr { get; set; }
            public int signature_length { get; set; }
        }

        public class SHAED25519DalekDigitialSignatureResult
        {
            public byte[] PublicKey { get; set; }
            public byte[] Signature { get; set; }
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
                SHARSADigitialSignatureResult result = DigitalSignatureLinuxWrapper.sha_512_rsa_digital_signature(rsaKeySize, dataToSign, dataToSign.Length);
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
                SHARSADigitialSignatureResult result = DigitalSignatureWindowsWrapper.sha_512_rsa_digital_signature(rsaKeySize, dataToSign, dataToSign.Length);
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
                SHAED25519DalekDigitalSignatureResult signatureResult = DigitalSignatureLinuxWrapper.sha512_ed25519_digital_signature(dataToSign, dataToSign.Length);
                byte[] publicKey = new byte[signatureResult.public_key_length];
                Marshal.Copy(signatureResult.public_key, publicKey, 0, signatureResult.public_key_length);
                byte[] signature = new byte[signatureResult.signature_length];
                Marshal.Copy(signatureResult.signature_raw_ptr, signature, 0, signatureResult.signature_length);
                DigitalSignatureLinuxWrapper.free_bytes(signatureResult.public_key);
                DigitalSignatureLinuxWrapper.free_bytes(signatureResult.signature_length);
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
                SHAED25519DalekDigitalSignatureResult signatureResult = DigitalSignatureWindowsWrapper.sha512_ed25519_digital_signature(dataToSign, dataToSign.Length);
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
    }
}
