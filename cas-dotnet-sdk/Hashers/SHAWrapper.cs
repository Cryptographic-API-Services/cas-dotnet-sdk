using CasDotnetSdk.Hashers.Linux;
using CasDotnetSdk.Hashers.Types;
using CasDotnetSdk.Hashers.Windows;
using CasDotnetSdk.Helpers;
using CASHelpers.Types.HttpResponses.BenchmarkAPI;
using System;
using System.Reflection;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Hashers
{
    public class SHAWrapper : BaseWrapper, IHasherBase
    {

        /// <summary>
        /// A wrapper class for the SHA3 256 and 512 hashing algorithms.
        /// </summary>
        public SHAWrapper()
        {
        }

        /// <summary>
        /// Hashes data using the SHA3 512 algorithm.
        /// </summary>
        /// <param name="dataToHash"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
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
            SHAHashByteResult hashedPtr = (this._platform == OSPlatform.Linux) ?
                SHALinuxWrapper.sha512_bytes(dataToHash, dataToHash.Length) :
                SHAWindowsWrapper.sha512_bytes(dataToHash, dataToHash.Length);
            byte[] result = new byte[hashedPtr.length];
            Marshal.Copy(hashedPtr.result_bytes_ptr, result, 0, hashedPtr.length);
            FreeMemoryHelper.FreeBytesMemory(hashedPtr.result_bytes_ptr);
            DateTime end = DateTime.UtcNow;
            this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(SHAWrapper));
            return result;
        }

        /// <summary>
        /// Hashes data using the SHA3 256 algorithm.
        /// </summary>
        /// <param name="dataToHash"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
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
            SHAHashByteResult hashedPtr = (this._platform == OSPlatform.Linux) ?
                SHALinuxWrapper.sha256_bytes(dataToHash, dataToHash.Length) :
                SHAWindowsWrapper.sha256_bytes(dataToHash, dataToHash.Length);
            byte[] result = new byte[hashedPtr.length];
            Marshal.Copy(hashedPtr.result_bytes_ptr, result, 0, hashedPtr.length);
            FreeMemoryHelper.FreeBytesMemory(hashedPtr.result_bytes_ptr);
            DateTime end = DateTime.UtcNow;
            this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(SHAWrapper));
            return result;
        }

        /// <summary>
        /// Verifies data using the SHA3 512 algorithm.
        /// </summary>
        /// <param name="dataToVerify"></param>
        /// <param name="hashedData"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
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
            bool result = (this._platform == OSPlatform.Linux) ?
                SHALinuxWrapper.sha512_bytes_verify(dataToVerify, dataToVerify.Length, hashedData, hashedData.Length) :
                SHAWindowsWrapper.sha512_bytes_verify(dataToVerify, dataToVerify.Length, hashedData, hashedData.Length);
            DateTime end = DateTime.UtcNow;
            this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(SHAWrapper));
            return result;
        }

        /// <summary>
        /// Verifies data using the SHA3 256 algorithm.
        /// </summary>
        /// <param name="dataToVerify"></param>
        /// <param name="hashedData"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
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
            bool result = (this._platform == OSPlatform.Linux) ?
                SHALinuxWrapper.sha256_bytes_verify(dataToVerify, dataToVerify.Length, hashedData, hashedData.Length) :
                SHAWindowsWrapper.sha256_bytes_verify(dataToVerify, dataToVerify.Length, hashedData, hashedData.Length);
            DateTime end = DateTime.UtcNow;
            this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(SHAWrapper));
            return result;
        }
    }
}