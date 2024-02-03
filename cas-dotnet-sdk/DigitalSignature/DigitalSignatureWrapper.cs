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


        public SHAED25519DalekDigitialSignatureResult SHA256ED25519DigitialSignature(byte[] dataToSign)
        {
            if (dataToSign == null || dataToSign.Length == 0)
            {
                throw new Exception("You must provide an allocated array of data to sign to create a SHA256 Ed25519 Digital Signature");
            }

            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                SHAED25519DalekStructDigitalSignatureResult structResult = DigitalSignatureLinuxWrapper.sha256_ed25519_digital_signature(dataToSign, dataToSign.Length);
                byte[] publicKey = new byte[structResult.public_key_length];
                byte[] signature = new byte[structResult.signature_length];
                Marshal.Copy(structResult.public_key, publicKey, 0, publicKey.Length);
                Marshal.Copy(structResult.signature_raw_ptr, signature, 0, signature.Length);
                DigitalSignatureLinuxWrapper.free_bytes(structResult.public_key);
                DigitalSignatureLinuxWrapper.free_bytes(structResult.signature_raw_ptr);
                SHAED25519DalekDigitialSignatureResult result = new SHAED25519DalekDigitialSignatureResult()
                {
                    PublicKey = publicKey,
                    Signature = signature
                };
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.DigitalSignature, nameof(DigitalSignatureWrapper));
                return result;
            }
            else
            {
                SHAED25519DalekStructDigitalSignatureResult structResult = DigitalSignatureWindowsWrapper.sha256_ed25519_digital_signature(dataToSign, dataToSign.Length);
                byte[] publicKey = new byte[structResult.public_key_length];
                byte[] signature = new byte[structResult.signature_length];
                Marshal.Copy(structResult.public_key, publicKey, 0, publicKey.Length);
                Marshal.Copy(structResult.signature_raw_ptr, signature, 0, signature.Length);
                DigitalSignatureWindowsWrapper.free_bytes(structResult.public_key);
                DigitalSignatureWindowsWrapper.free_bytes(structResult.signature_raw_ptr);
                SHAED25519DalekDigitialSignatureResult result = new SHAED25519DalekDigitialSignatureResult()
                {
                    PublicKey = publicKey,
                    Signature = signature
                };
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.DigitalSignature, nameof(DigitalSignatureWrapper));
                return result;
            }
        }

        public bool SHA256ED25519DigitialSignatureVerify(byte[] publicKey, byte[] dataToVerify, byte[] signature)
        {
            if (publicKey == null || publicKey.Length == 0)
            {
                throw new Exception("You must provide an allocated public key");
            }
            if (dataToVerify == null || dataToVerify.Length == 0)
            {
                throw new Exception("You must provide an allocated data to verify");
            }
            if (signature == null || signature.Length == 0)
            {
                throw new Exception("You must provide an allocated signature ");
            }

            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                bool result = DigitalSignatureLinuxWrapper.sha256_ed25519_digital_signature_verify(publicKey, publicKey.Length, dataToVerify, dataToVerify.Length, signature, signature.Length);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.DigitalSignature, nameof(DigitalSignatureWrapper));
                return result;
            }
            else
            {
                bool result = DigitalSignatureWindowsWrapper.sha256_ed25519_digital_signature_verify(publicKey, publicKey.Length, dataToVerify, dataToVerify.Length, signature, signature.Length);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.DigitalSignature, nameof(DigitalSignatureWrapper));
                return result;
            }
        }
    }
}