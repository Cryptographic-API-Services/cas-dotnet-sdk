using CasDotnetSdk.Hashers.Linux;
using CasDotnetSdk.Hashers.Types;
using CasDotnetSdk.Hashers.Windows;
using CasDotnetSdk.Http;
using CASHelpers;
using CASHelpers.Types.HttpResponses.BenchmarkAPI;
using System;
using System.Reflection;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Hashers
{
    public class HmacWrapper
    {
        private readonly OSPlatform _platform;
        private readonly BenchmarkSender _benchmarkSender;

        public HmacWrapper()
        {
            this._platform = new OperatingSystemDeterminator().GetOperatingSystem();
            this._benchmarkSender = new BenchmarkSender();
        }

        public byte[] HmacSignBytes(byte[] key, byte[] message)
        {
            if (key == null || key.Length == 0)
            {
                throw new Exception("You must provide a key to sign with HMAC");
            }
            if (message == null || message.Length == 0)
            {
                throw new Exception("You must provide a message to sign with HMAC");
            }
            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                HmacSignByteResult signed = HmacLinuxWrapper.hmac_sign_bytes(key, key.Length, message, message.Length);
                byte[] result = new byte[signed.length];
                Marshal.Copy(signed.result_bytes_ptr, result, 0, signed.length);
                HmacLinuxWrapper.free_bytes(signed.result_bytes_ptr);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(HmacWrapper));
                return result;
            }
            else
            {
                HmacSignByteResult signed = HmacWindowsWrapper.hmac_sign_bytes(key, key.Length, message, message.Length);
                byte[] result = new byte[signed.length];
                Marshal.Copy(signed.result_bytes_ptr, result, 0, signed.length);
                HmacWindowsWrapper.free_bytes(signed.result_bytes_ptr);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(HmacWrapper));
                return result;
            }
        }

        public bool HmacVerifyBytes(byte[] key, byte[] message, byte[] signature)
        {
            if (key == null || key.Length == 0)
            {
                throw new Exception("You must provide a key to verify with HMAC");
            }
            if (message == null || message.Length == 0)
            {
                throw new Exception("You must provide a message to verify with HMAC");
            }

            DateTime start = DateTime.UtcNow;
            if (signature == null || signature.Length == 0)
            {
                throw new Exception("You must provide a signature to verify with HMAC");
            }
            if (this._platform == OSPlatform.Linux)
            {
                bool result = HmacLinuxWrapper.hmac_verify_bytes(key, key.Length, message, message.Length, signature, signature.Length);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(HmacWrapper));
                return result;
            }
            else
            {
                bool result = HmacWindowsWrapper.hmac_verify_bytes(key, key.Length, message, message.Length, signature, signature.Length);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(HmacWrapper));
                return result;
            }
        }
    }
}