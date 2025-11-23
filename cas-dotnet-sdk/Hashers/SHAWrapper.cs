using CasDotnetSdk.Fodies;
using CasDotnetSdk.Hashers.Linux;
using CasDotnetSdk.Hashers.Types;
using CasDotnetSdk.Hashers.Windows;
using CasDotnetSdk.Helpers;
using System;
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
        /// 
        [BenchmarkSender]
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
            
            SHAHashByteResult hashedPtr = (this._platform == OSPlatform.Linux) ?
                SHALinuxWrapper.sha512_bytes(dataToHash, dataToHash.Length) :
                SHAWindowsWrapper.sha512_bytes(dataToHash, dataToHash.Length);
            byte[] result = new byte[hashedPtr.length];
            Marshal.Copy(hashedPtr.result_bytes_ptr, result, 0, hashedPtr.length);
            FreeMemoryHelper.FreeBytesMemory(hashedPtr.result_bytes_ptr);
            

            return result;
        }

        /// <summary>
        /// Hashes data using the SHA3 256 algorithm.
        /// </summary>
        /// <param name="dataToHash"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        /// 
        [BenchmarkSender]
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
            
            SHAHashByteResult hashedPtr = (this._platform == OSPlatform.Linux) ?
                SHALinuxWrapper.sha256_bytes(dataToHash, dataToHash.Length) :
                SHAWindowsWrapper.sha256_bytes(dataToHash, dataToHash.Length);
            byte[] result = new byte[hashedPtr.length];
            Marshal.Copy(hashedPtr.result_bytes_ptr, result, 0, hashedPtr.length);
            FreeMemoryHelper.FreeBytesMemory(hashedPtr.result_bytes_ptr);
            

            return result;
        }

        /// <summary>
        /// Verifies data using the SHA3 512 algorithm.
        /// </summary>
        /// <param name="dataToVerify"></param>
        /// <param name="hashedData"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        /// 
        [BenchmarkSender]
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
            
            bool result = (this._platform == OSPlatform.Linux) ?
                SHALinuxWrapper.sha512_bytes_verify(dataToVerify, dataToVerify.Length, hashedData, hashedData.Length) :
                SHAWindowsWrapper.sha512_bytes_verify(dataToVerify, dataToVerify.Length, hashedData, hashedData.Length);
            

            return result;
        }

        /// <summary>
        /// Verifies data using the SHA3 256 algorithm.
        /// </summary>
        /// <param name="dataToVerify"></param>
        /// <param name="hashedData"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        /// 
        [BenchmarkSender]
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
            
            bool result = (this._platform == OSPlatform.Linux) ?
                SHALinuxWrapper.sha256_bytes_verify(dataToVerify, dataToVerify.Length, hashedData, hashedData.Length) :
                SHAWindowsWrapper.sha256_bytes_verify(dataToVerify, dataToVerify.Length, hashedData, hashedData.Length);
            

            return result;
        }
    }
}