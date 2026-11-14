using CasCoreLib;

namespace CasDotnetSdk.Hashers
{
    public unsafe class SHAWrapper : IHasherBase
    {
        /// <summary>
        /// A wrapper class for the SHA3 256 and 512 hashing algorithms (FIPS 202).
        /// For SHA-2 (SHA-256 / SHA-512), use <see cref="SHA2Wrapper"/>.
        /// </summary>
        public SHAWrapper()
        {
        }

        /// <summary>
        /// Hashes data using the SHA3 512 algorithm.
        /// </summary>
        /// <param name="dataToHash">The data to hash. <c>null</c> and an empty array are both hashed as the empty message.</param>
        public byte[] Hash512(byte[]? dataToHash)
        {
            return ShaNative.Hash(dataToHash, NativeMethods.sha3_512_bytes);
        }

        /// <summary>
        /// Hashes data using the SHA3 256 algorithm.
        /// </summary>
        /// <param name="dataToHash">The data to hash. <c>null</c> and an empty array are both hashed as the empty message.</param>
        public byte[] Hash256(byte[]? dataToHash)
        {
            return ShaNative.Hash(dataToHash, NativeMethods.sha3_256_bytes);
        }

        /// <summary>
        /// Verifies data using the SHA3 512 algorithm.
        /// </summary>
        /// <param name="dataToVerify">The original data. <c>null</c> and an empty array are both treated as the empty message.</param>
        /// <param name="hashedData">The SHA3 512 digest to check against.</param>
        public bool Verify512(byte[]? dataToVerify, byte[] hashedData)
        {
            return ShaNative.Verify(dataToVerify, hashedData, nameof(hashedData), NativeMethods.sha3_512_bytes_verify);
        }

        /// <summary>
        /// Verifies data using the SHA3 256 algorithm.
        /// </summary>
        /// <param name="dataToVerify">The original data. <c>null</c> and an empty array are both treated as the empty message.</param>
        /// <param name="hashedData">The SHA3 256 digest to check against.</param>
        public bool Verify256(byte[]? dataToVerify, byte[] hashedData)
        {
            return ShaNative.Verify(dataToVerify, hashedData, nameof(hashedData), NativeMethods.sha3_256_bytes_verify);
        }
    }
}
