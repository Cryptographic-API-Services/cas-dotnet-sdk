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
    public class Blake2Wrapper : IHasherBase
    {
        private readonly OSPlatform _platform;
        private readonly BenchmarkSender _sender;

        /// <summary>
        /// A wrapper class for the Blake2 hashing algorithm.
        /// </summary>
        public Blake2Wrapper()
        {
            this._platform = new OperatingSystemDeterminator().GetOperatingSystem();
            this._sender = new BenchmarkSender();
        }

        /// <summary>
        /// Hashes data using the Blake2 512 algorithm.
        /// </summary>
        /// <param name="toHash"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public byte[] Hash512(byte[] toHash)
        {
            if (toHash == null || toHash.Length == 0)
            {
                throw new Exception("You must provide datat to hash with Blake 2 512");
            }

            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                Blake2HashByteResult hashResult = Blake2LinuxWrapper.blake2_512_bytes(toHash, toHash.Length);
                byte[] result = new byte[hashResult.length];
                Marshal.Copy(hashResult.result_bytes_ptr, result, 0, hashResult.length);
                Blake2LinuxWrapper.free_bytes(hashResult.result_bytes_ptr);
                DateTime end = DateTime.UtcNow;
                this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(Blake2Wrapper));
                return result;
            }
            else
            {
                Blake2HashByteResult hashResult = Blake2WindowsWrapper.blake2_512_bytes(toHash, toHash.Length);
                byte[] result = new byte[hashResult.length];
                Marshal.Copy(hashResult.result_bytes_ptr, result, 0, hashResult.length);
                Blake2WindowsWrapper.free_bytes(hashResult.result_bytes_ptr);
                DateTime end = DateTime.UtcNow;
                this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(Blake2Wrapper));
                return result;
            }
        }

        /// <summary>
        /// Verifies data using the Blake2 512 algorithm.
        /// </summary>
        /// <param name="hashedData"></param>
        /// <param name="toCompare"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public bool Verify512(byte[] hashedData, byte[] toCompare)
        {
            if (hashedData == null || hashedData.Length == 0)
            {
                throw new Exception("You must provide previously hashed data to verify with Blake 2 512");
            }
            if (toCompare == null || toCompare.Length == 0)
            {
                throw new Exception("You must provide data to compare to verify with Blake 2 512");
            }

            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                bool result = Blake2LinuxWrapper.blake2_512_bytes_verify(hashedData, hashedData.Length, toCompare, toCompare.Length);
                DateTime end = DateTime.UtcNow;
                this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(Blake2Wrapper));
                return result;
            }
            else
            {
                bool result = Blake2WindowsWrapper.blake2_512_bytes_verify(hashedData, hashedData.Length, toCompare, toCompare.Length);
                DateTime end = DateTime.UtcNow;
                this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(Blake2Wrapper));
                return result;
            }
        }

        /// <summary>
        /// Hashes data using the Blake2 256 algorithm.
        /// </summary>
        /// <param name="toHash"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public byte[] Hash256(byte[] toHash)
        {
            if (toHash == null || toHash.Length == 0)
            {
                throw new Exception("You must provide an array of allocated data to hash with Blake2 256");
            }

            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                Blake2HashByteResult hashedResult = Blake2LinuxWrapper.blake2_256_bytes(toHash, toHash.Length);
                byte[] result = new byte[hashedResult.length];
                Marshal.Copy(hashedResult.result_bytes_ptr, result, 0, result.Length);
                Blake2LinuxWrapper.free_bytes(hashedResult.result_bytes_ptr);
                DateTime end = DateTime.UtcNow;
                this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(Blake2Wrapper));
                return result;
            }
            else
            {
                Blake2HashByteResult hashedResult = Blake2WindowsWrapper.blake2_256_bytes(toHash, toHash.Length);
                byte[] result = new byte[hashedResult.length];
                Marshal.Copy(hashedResult.result_bytes_ptr, result, 0, result.Length);
                Blake2WindowsWrapper.free_bytes(hashedResult.result_bytes_ptr);
                DateTime end = DateTime.UtcNow;
                this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(Blake2Wrapper));
                return result;
            }
        }

        /// <summary>
        /// Verifies data using the Blake2 256 algorithm.
        /// </summary>
        /// <param name="hashedData"></param>
        /// <param name="toCompare"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public bool Verify256(byte[] hashedData, byte[] toCompare)
        {
            if (hashedData == null || hashedData.Length == 0)
            {
                throw new Exception("You must provide allocated data for the previously hashed data to compare with Blake 2 256");
            }
            if (toCompare == null || toCompare.Length == 0)
            {
                throw new Exception("You must provide allocated data for the data to compare with Blake 2 256");
            }

            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                bool result = Blake2LinuxWrapper.blake2_256_bytes_verify(hashedData, hashedData.Length, toCompare, toCompare.Length);
                DateTime end = DateTime.UtcNow;
                this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(Blake2Wrapper));
                return result;
            }
            else
            {
                bool result = Blake2WindowsWrapper.blake2_256_bytes_verify(hashedData, hashedData.Length, toCompare, toCompare.Length);
                DateTime end = DateTime.UtcNow;
                this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(Blake2Wrapper));
                return result;
            }
        }
    }
}