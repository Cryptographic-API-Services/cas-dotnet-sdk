﻿using CasDotnetSdk.Hashers.Linux;
using CasDotnetSdk.Hashers.Types;
using CasDotnetSdk.Hashers.Windows;
using CasDotnetSdk.Helpers;
using CasDotnetSdk.Http;
using CASHelpers;
using CASHelpers.Types.HttpResponses.BenchmarkAPI;
using System;
using System.Reflection;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Hashers
{
    public class Blake2Wrapper : BaseWrapper, IHasherBase
    {

        /// <summary>
        /// A wrapper class for the Blake2 hashing algorithm.
        /// </summary>
        public Blake2Wrapper()
        {

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
                throw new Exception("You must provide data to hash with Blake 2 512");
            }

            DateTime start = DateTime.UtcNow;
            Blake2HashByteResult hashResult = (this._platform == OSPlatform.Linux) ?
                Blake2LinuxWrapper.blake2_512_bytes(toHash, toHash.Length) :
                Blake2WindowsWrapper.blake2_512_bytes(toHash, toHash.Length);
            byte[] result = new byte[hashResult.length];
            Marshal.Copy(hashResult.result_bytes_ptr, result, 0, hashResult.length);
            FreeMemoryHelper.FreeBytesMemory(hashResult.result_bytes_ptr);
            DateTime end = DateTime.UtcNow;
            this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(Blake2Wrapper));
            return result;
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
            bool result = (this._platform == OSPlatform.Linux) ?
                Blake2LinuxWrapper.blake2_512_bytes_verify(hashedData, hashedData.Length, toCompare, toCompare.Length) :
                Blake2WindowsWrapper.blake2_512_bytes_verify(hashedData, hashedData.Length, toCompare, toCompare.Length);
            DateTime end = DateTime.UtcNow;
            this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(Blake2Wrapper));
            return result;
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
            Blake2HashByteResult hashedResult = (this._platform == OSPlatform.Linux) ?
                Blake2LinuxWrapper.blake2_256_bytes(toHash, toHash.Length) :
                Blake2WindowsWrapper.blake2_256_bytes(toHash, toHash.Length);
            byte[] result = new byte[hashedResult.length];
            Marshal.Copy(hashedResult.result_bytes_ptr, result, 0, result.Length);
            FreeMemoryHelper.FreeBytesMemory(hashedResult.result_bytes_ptr);
            DateTime end = DateTime.UtcNow;
            this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(Blake2Wrapper));
            return result;
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
            bool result = (this._platform == OSPlatform.Linux) ?
                Blake2LinuxWrapper.blake2_256_bytes_verify(hashedData, hashedData.Length, toCompare, toCompare.Length) :
                Blake2WindowsWrapper.blake2_256_bytes_verify(hashedData, hashedData.Length, toCompare, toCompare.Length);
            DateTime end = DateTime.UtcNow;
            this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(Blake2Wrapper));
            return result;
        }
    }
}