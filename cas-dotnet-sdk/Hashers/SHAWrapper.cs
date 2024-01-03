using CasDotnetSdk.Hashers.Linux;
using CasDotnetSdk.Hashers.Windows;
using CasDotnetSdk.Http;
using CASHelpers;
using CASHelpers.Types.HttpResponses.BenchmarkAPI;
using System;
using System.Reflection;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Hashers
{
    public class SHAWrapper
    {
        private readonly OSPlatform _platform;
        private readonly BenchmarkSender _benchmarkSender;
        public SHAWrapper()
        {
            this._platform = new OperatingSystemDeterminator().GetOperatingSystem();
            this._benchmarkSender = new BenchmarkSender();
        }

        internal struct SHAHashByteResult
        {
            public IntPtr result_bytes_ptr;
            public int length;
        }

        public byte[] SHA512HashBytes(byte[] dataToHash)
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
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash);
                return result;
            }
            else
            {
                SHAHashByteResult hashedPtr = SHAWindowsWrapper.sha512_bytes(dataToHash, dataToHash.Length);
                byte[] result = new byte[hashedPtr.length];
                Marshal.Copy(hashedPtr.result_bytes_ptr, result, 0, hashedPtr.length);
                SHAWindowsWrapper.free_bytes(hashedPtr.result_bytes_ptr);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash);
                return result;
            }
        }

        public byte[] SHA256HashBytes(byte[] dataToHash)
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
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash);
                return result;
            }
            else
            {
                SHAHashByteResult hashedPtr = SHAWindowsWrapper.sha256_bytes(dataToHash, dataToHash.Length);
                byte[] result = new byte[hashedPtr.length];
                Marshal.Copy(hashedPtr.result_bytes_ptr, result, 0, hashedPtr.length);
                SHAWindowsWrapper.free_bytes(hashedPtr.result_bytes_ptr);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash);
                return result;
            }
        }
    }
}