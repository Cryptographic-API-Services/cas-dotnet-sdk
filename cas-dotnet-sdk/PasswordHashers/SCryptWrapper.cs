using CasCoreLib;
using CasDotnetSdk.Helpers;
using System;
using System.Security.Cryptography;

namespace CasDotnetSdk.PasswordHashers
{
    public unsafe class SCryptWrapper : IPasswordHasherBase
    {
        /// <summary>The smallest <c>cpuCost</c> (log2 N) accepted.</summary>
        public const int MinCpuCost = 10;
        /// <summary>The largest <c>cpuCost</c> (log2 N) accepted.</summary>
        public const int MaxCpuCost = 20;
        /// <summary>The smallest <c>blockSize</c> (r) accepted.</summary>
        public const int MinBlockSize = 1;
        /// <summary>The largest <c>blockSize</c> (r) accepted.</summary>
        public const int MaxBlockSize = 32;
        /// <summary>The smallest <c>parallelism</c> (p) accepted.</summary>
        public const int MinParallelism = 1;
        /// <summary>The largest <c>parallelism</c> (p) accepted.</summary>
        public const int MaxParallelism = 16;

        /// <summary>
        /// A wrapper class that uses the SCrypt algorithm to hash passwords.
        /// </summary>
        public SCryptWrapper()
        {
        }

        /// <summary>
        /// Hashes a password using the SCrypt algorithm with the default parameters. The whole UTF-8 encoding
        /// of the password is hashed, including any <c>'\0'</c>.
        /// </summary>
        /// <exception cref="ArgumentNullException"><paramref name="passToHash"/> is null.</exception>
        /// <exception cref="ArgumentException"><paramref name="passToHash"/> is empty.</exception>
        public string HashPassword(string passToHash)
        {
            PasswordBytes.Validate(passToHash, nameof(passToHash));

            byte[] passwordBytes = PasswordBytes.Encode(passToHash);
            try
            {
                fixed (byte* passPtr = passwordBytes)
                {
                    CasStringResult hashResult = NativeMethods.scrypt_hash_bytes(passPtr, (nuint)passwordBytes.Length);
                    CasErrorHandler.ThrowIfError(hashResult.error_code, "SCrypt hash");
                    return NativeString.ReadAndFree(hashResult.value);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(passwordBytes);
            }
        }

        /// <summary>
        /// Hashes a password using the SCrypt algorithm with specified parameters. Memory use is about
        /// 128 * blockSize * 2^cpuCost bytes. The whole UTF-8 encoding of the password is hashed, including any <c>'\0'</c>.
        /// </summary>
        /// <param name="passToHash">The password to hash. Must not be null or empty.</param>
        /// <param name="cpuCost">CPU/memory cost as log2(N); 17 (the default) means N = 131072. From 10 to 20, and less than 16 * <paramref name="blockSize"/>.</param>
        /// <param name="blockSize">Block size (r). Default 8, from 1 to 32.</param>
        /// <param name="parallelism">Parallelization (p). Default 1, from 1 to 16.</param>
        /// <exception cref="ArgumentNullException"><paramref name="passToHash"/> is null.</exception>
        /// <exception cref="ArgumentException"><paramref name="passToHash"/> is empty.</exception>
        /// <exception cref="ArgumentOutOfRangeException">A cost parameter is outside its range.</exception>
        public string HashPasswordWithParameters(string passToHash, int cpuCost = 17, int blockSize = 8, int parallelism = 1)
        {
            PasswordBytes.Validate(passToHash, nameof(passToHash));
            if (cpuCost < MinCpuCost || cpuCost > MaxCpuCost)
            {
                throw new ArgumentOutOfRangeException(nameof(cpuCost), cpuCost, $"The SCrypt CPU cost (log2 N) must be between {MinCpuCost} and {MaxCpuCost}.");
            }
            if (blockSize < MinBlockSize || blockSize > MaxBlockSize)
            {
                throw new ArgumentOutOfRangeException(nameof(blockSize), blockSize, $"The SCrypt block size must be between {MinBlockSize} and {MaxBlockSize}.");
            }
            if (parallelism < MinParallelism || parallelism > MaxParallelism)
            {
                throw new ArgumentOutOfRangeException(nameof(parallelism), parallelism, $"The SCrypt parallelism must be between {MinParallelism} and {MaxParallelism}.");
            }
            // scrypt requires N < 2^(16 * r).
            if (cpuCost >= 16 * blockSize)
            {
                throw new ArgumentOutOfRangeException(nameof(cpuCost), cpuCost, $"The SCrypt CPU cost (log2 N) must be less than 16 times the block size ({16 * blockSize}).");
            }

            byte[] passwordBytes = PasswordBytes.Encode(passToHash);
            try
            {
                fixed (byte* passPtr = passwordBytes)
                {
                    CasStringResult hashResult = NativeMethods.scrypt_hash_with_parameters_bytes(passPtr, (nuint)passwordBytes.Length, checked((byte)cpuCost), checked((uint)blockSize), checked((uint)parallelism));
                    CasErrorHandler.ThrowIfError(hashResult.error_code, "SCrypt hash");
                    return NativeString.ReadAndFree(hashResult.value);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(passwordBytes);
            }
        }

        /// <summary>
        /// Verifies an unhashed password against a hashed password using the SCrypt algorithm.
        /// </summary>
        /// <exception cref="ArgumentNullException">An argument is null.</exception>
        /// <exception cref="ArgumentException">An argument is empty.</exception>
        /// <exception cref="CasException">The hash can't be parsed, or its cost parameters exceed the limits above.</exception>
        public bool Verify(string hashedPassword, string password)
        {
            if (hashedPassword == null)
            {
                throw new ArgumentNullException(nameof(hashedPassword));
            }
            if (hashedPassword.Length == 0)
            {
                throw new ArgumentException("The hashed password must not be empty.", nameof(hashedPassword));
            }
            PasswordBytes.Validate(password, nameof(password));

            byte[] passwordBytes = PasswordBytes.Encode(password);
            try
            {
                fixed (byte* hashPtr = NativeString.ToCString(hashedPassword))
                fixed (byte* passPtr = passwordBytes)
                {
                    CasVerifyResult result = NativeMethods.scrypt_verify_bytes(hashPtr, passPtr, (nuint)passwordBytes.Length);
                    CasErrorHandler.ThrowIfError(result.error_code, "SCrypt verify");
                    return result.is_valid;
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(passwordBytes);
            }
        }
    }
}
