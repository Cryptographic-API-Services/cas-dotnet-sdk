using CasDotnetSdk.Hashers.Linux;
using CasDotnetSdk.Hashers.Types;
using CasDotnetSdk.Hashers.Windows;
using CasDotnetSdk.Http;
using CASHelpers;
using CASHelpers.Types.HttpResponses.BenchmarkAPI;
using System;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Hashers
{
    public class SHAWrapper : IHasherBase
    {
        private readonly OSPlatform _platform;
        private readonly BenchmarkSender _benchmarkSender;
        public SHAWrapper()
        {
            this._platform = new OperatingSystemDeterminator().GetOperatingSystem();
            this._benchmarkSender = new BenchmarkSender();
        }

        public byte[] Hash512(byte[] dataToHash)
        {
            if (dataToHash == null)
            {
                throw new Exception("You must provide a byte array of data to hash");
            }
            if (dataToHash.Length == 0)
            {
                throw new Exception("You must provide a byte array with allocated data to hash");
            }
            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                SHAHashByteResult hashedPtr = SHALinuxWrapper.sha512_bytes(dataToHash, dataToHash.Length);
                byte[] result = new byte[hashedPtr.length];
                Marshal.Copy(hashedPtr.result_bytes_ptr, result, 0, hashedPtr.length);
                SHALinuxWrapper.free_bytes(hashedPtr.result_bytes_ptr);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(SHAWrapper));
                return result;
            }
            else
            {
                SHAHashByteResult hashedPtr = SHAWindowsWrapper.sha512_bytes(dataToHash, dataToHash.Length);
                byte[] result = new byte[hashedPtr.length];
                Marshal.Copy(hashedPtr.result_bytes_ptr, result, 0, hashedPtr.length);
                SHAWindowsWrapper.free_bytes(hashedPtr.result_bytes_ptr);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(SHAWrapper));
                return result;
            }
        }

        public byte[] Hash256(byte[] dataToHash)
        {
            if (dataToHash == null)
            {
                throw new Exception("You must provide a byte array of data to hash");
            }
            if (dataToHash.Length == 0)
            {
                throw new Exception("You must provide a byte array with allocated data to hash");
            }
            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                SHAHashByteResult hashedPtr = SHALinuxWrapper.sha256_bytes(dataToHash, dataToHash.Length);
                byte[] result = new byte[hashedPtr.length];
                Marshal.Copy(hashedPtr.result_bytes_ptr, result, 0, hashedPtr.length);
                SHALinuxWrapper.free_bytes(hashedPtr.result_bytes_ptr);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(SHAWrapper));
                return result;
            }
            else
            {
                SHAHashByteResult hashedPtr = SHAWindowsWrapper.sha256_bytes(dataToHash, dataToHash.Length);
                byte[] result = new byte[hashedPtr.length];
                Marshal.Copy(hashedPtr.result_bytes_ptr, result, 0, hashedPtr.length);
                SHAWindowsWrapper.free_bytes(hashedPtr.result_bytes_ptr);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(SHAWrapper));
                return result;
            }
        }

        public bool Verify512(byte[] dataToVerify, byte[] hashedData)
        {
            if (dataToVerify == null || dataToVerify.Length == 0)
            {
                throw new Exception("You must provide a byte array with allocated data to verify");
            }
            if (hashedData == null || hashedData.Length == 0)
            {
                throw new Exception("You must provide a byte array with allocated data to verify");
            }
            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                bool result = SHALinuxWrapper.sha512_bytes_verify(dataToVerify, dataToVerify.Length, hashedData, hashedData.Length);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(SHAWrapper));
                return result;
            }
            else
            {
                bool result = SHAWindowsWrapper.sha512_bytes_verify(dataToVerify, dataToVerify.Length, hashedData, hashedData.Length);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(SHAWrapper));
                return result;
            }
        }

        public bool Verify256(byte[] dataToVerify, byte[] hashedData)
        {
            if (dataToVerify == null || dataToVerify.Length == 0)
            {
                throw new Exception("You must provide a byte array with allocated data to verify");
            }
            if (hashedData == null || hashedData.Length == 0)
            {
                throw new Exception("You must provide a byte array with allocated data to verify");
            }
            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                bool result = SHALinuxWrapper.sha256_bytes_verify(dataToVerify, dataToVerify.Length, hashedData, hashedData.Length);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(SHAWrapper));
                return result;
            }
            else
            {
                bool result = SHAWindowsWrapper.sha256_bytes_verify(dataToVerify, dataToVerify.Length, hashedData, hashedData.Length);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(SHAWrapper));
                return result;
            }
        }
    }
}