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

        public SHARSADigitalSignatureResult SHARSADigitalSignature(int rsaKeySize, byte[] dataToSign)
        {
            if (rsaKeySize != 1024 && rsaKeySize != 2048 && rsaKeySize != 4096)
            {
                throw new Exception("Not a valid RSA key size");
            }
            if (dataToSign == null || dataToSign.Length ==0)
            {
                throw new Exception("Must provide an allocated data set to sign");
            }

            DateTime start = DateTime.Now;
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
                DateTime end = DateTime.Now;
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
                DateTime end = DateTime.Now;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.DigitalSignature, nameof(DigitalSignatureWrapper));
                return new SHARSADigitalSignatureResult()
                {
                    PrivateKey = privateKey,
                    PublicKey = publicKey,
                    Signature = signature
                };
            }
        }
    }
}
