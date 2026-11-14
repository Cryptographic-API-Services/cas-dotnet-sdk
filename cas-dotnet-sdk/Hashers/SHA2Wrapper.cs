using CasCoreLib;

namespace CasDotnetSdk.Hashers
{
    public unsafe class SHA2Wrapper : IHasherBase
    {
        /// <summary>
        /// A wrapper class for the SHA-256 and SHA-512 hashing algorithms (SHA-2, FIPS 180-4).
        /// For SHA-3, use <see cref="SHAWrapper"/>.
        /// </summary>
        public SHA2Wrapper()
        {
        }

        /// <summary>
        /// Hashes data using the SHA-512 algorithm.
        /// </summary>
        /// <param name="dataToHash">The data to hash. <c>null</c> and an empty array are both hashed as the empty message.</param>
        public byte[] Hash512(byte[]? dataToHash)
        {
            return ShaNative.Hash(dataToHash, NativeMethods.sha2_512_bytes);
        }

        /// <summary>
        /// Hashes data using the SHA-256 algorithm.
        /// </summary>
        /// <param name="dataToHash">The data to hash. <c>null</c> and an empty array are both hashed as the empty message.</param>
        public byte[] Hash256(byte[]? dataToHash)
        {
            return ShaNative.Hash(dataToHash, NativeMethods.sha2_256_bytes);
        }

        /// <summary>
        /// Verifies data using the SHA-512 algorithm.
        /// </summary>
        /// <param name="dataToVerify">The original data. <c>null</c> and an empty array are both treated as the empty message.</param>
        /// <param name="hashedData">The SHA-512 digest to check against.</param>
        public bool Verify512(byte[]? dataToVerify, byte[] hashedData)
        {
            return ShaNative.Verify(dataToVerify, hashedData, nameof(hashedData), NativeMethods.sha2_512_bytes_verify);
        }

        /// <summary>
        /// Verifies data using the SHA-256 algorithm.
        /// </summary>
        /// <param name="dataToVerify">The original data. <c>null</c> and an empty array are both treated as the empty message.</param>
        /// <param name="hashedData">The SHA-256 digest to check against.</param>
        public bool Verify256(byte[]? dataToVerify, byte[] hashedData)
        {
            return ShaNative.Verify(dataToVerify, hashedData, nameof(hashedData), NativeMethods.sha2_256_bytes_verify);
        }
    }
}
