using CasCoreLib;
using CasDotnetSdk.Helpers;
using System;

namespace CasDotnetSdk.Hashers
{
    public unsafe class Blake2Wrapper : BaseWrapper, IHasherBase
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
        public byte[] Hash512(byte[] dataToHash)
        {
            ThrowIfNull(dataToHash, nameof(dataToHash));
            return Hash(dataToHash, NativeMethods.blake2_512_bytes);
        }

        /// <summary>
        /// Hashes data using the Blake2 256 algorithm.
        /// </summary>
        public byte[] Hash256(byte[] dataToHash)
        {
            ThrowIfNull(dataToHash, nameof(dataToHash));
            return Hash(dataToHash, NativeMethods.blake2_256_bytes);
        }

        /// <summary>
        /// Verifies data using the Blake2 512 algorithm.
        /// </summary>
        public bool Verify512(byte[] dataToVerify, byte[] hashedData)
        {
            ThrowIfNull(dataToVerify, nameof(dataToVerify));
            ThrowIfNull(hashedData, nameof(hashedData));
            return Verify(dataToVerify, hashedData, NativeMethods.blake2_512_bytes_verify);
        }

        /// <summary>
        /// Verifies data using the Blake2 256 algorithm.
        /// </summary>
        public bool Verify256(byte[] dataToVerify, byte[] hashedData)
        {
            ThrowIfNull(dataToVerify, nameof(dataToVerify));
            ThrowIfNull(hashedData, nameof(hashedData));
            return Verify(dataToVerify, hashedData, NativeMethods.blake2_256_bytes_verify);
        }

        private unsafe delegate Blake2HashByteResult HashFn(byte* data, nuint length);
        private unsafe delegate bool VerifyFn(byte* data, nuint dataLength, byte* hash, nuint hashLength);

        private static unsafe byte[] Hash(byte[] data, HashFn nativeHash)
        {
            fixed (byte* dataPtr = NativePin.Of(data))
            {
                Blake2HashByteResult result = nativeHash(dataPtr, (nuint)data.Length);
                return NativeByteBuffer.CopyAndFree(result.result_bytes_ptr, result.length);
            }
        }

        private static unsafe bool Verify(byte[] data, byte[] hash, VerifyFn nativeVerify)
        {
            fixed (byte* dataPtr = NativePin.Of(data))
            fixed (byte* hashPtr = NativePin.Of(hash))
            {
                return nativeVerify(dataPtr, (nuint)data.Length, hashPtr, (nuint)hash.Length);
            }
        }

        private static void ThrowIfNull(byte[] value, string paramName)
        {
            if (value == null)
            {
                throw new ArgumentNullException(paramName);
            }
        }
    }
}
