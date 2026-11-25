using CasCoreLib;
using CasDotnetSdk.Helpers;
using System;
using System.Security.Cryptography;

namespace CasDotnetSdk.PasswordHashers
{
    public unsafe class BcryptWrapper : IPasswordHasherBase
    {
        /// <summary>
        /// The longest password bcrypt accepts, in UTF-8 bytes (not characters). bcrypt only keys on the
        /// first 72 bytes, so longer passwords are rejected instead of being silently truncated.
        /// </summary>
        public const int MaxPasswordBytes = 72;
        /// <summary>The smallest <c>cost</c> accepted when hashing.</summary>
        public const uint MinCost = 10;
        /// <summary>The largest <c>cost</c> accepted when hashing, and the largest cost a stored hash may have when verifying.</summary>
        public const uint MaxCost = 16;

        /// <summary>
        /// A wrapper class that uses the BCrypt algorithm to hash passwords.
        /// </summary>
        public BcryptWrapper()
        {
        }

        /// <summary>
        /// Hashes a password using the BCrypt algorithm at the default cost (12). The whole UTF-8 encoding of
        /// the password is hashed, including any <c>'\0'</c>.
        /// </summary>
        /// <param name="passwordToHash">The password to hash: not null or empty, and at most 72 UTF-8 bytes (<see cref="MaxPasswordBytes"/>).</param>
        /// <exception cref="ArgumentNullException"><paramref name="passwordToHash"/> is null.</exception>
        /// <exception cref="ArgumentException"><paramref name="passwordToHash"/> is empty or longer than 72 UTF-8 bytes.</exception>
        public string HashPassword(string passwordToHash)
        {
            ValidatePassword(passwordToHash, nameof(passwordToHash));

            byte[] passwordBytes = PasswordBytes.Encode(passwordToHash);
            try
            {
                fixed (byte* passPtr = passwordBytes)
                {
                    CasStringResult hashResult = NativeMethods.bcrypt_hash_bytes(passPtr, (nuint)passwordBytes.Length);
                    CasErrorHandler.ThrowIfError(hashResult.error_code, "BCrypt hash");
                    return NativeString.ReadAndFree(hashResult.value);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(passwordBytes);
            }
        }

        /// <summary>
        /// Hashes a password using the BCrypt algorithm with the given cost. The whole UTF-8 encoding of the
        /// password is hashed, including any <c>'\0'</c>.
        /// </summary>
        /// <param name="passToHash">The password to hash: not null or empty, and at most 72 UTF-8 bytes (<see cref="MaxPasswordBytes"/>).</param>
        /// <param name="cost">Log2 work factor; each +1 doubles the hashing time. Default 12, from 10 (<see cref="MinCost"/>) to 16 (<see cref="MaxCost"/>).</param>
        /// <exception cref="ArgumentNullException"><paramref name="passToHash"/> is null.</exception>
        /// <exception cref="ArgumentException"><paramref name="passToHash"/> is empty or longer than 72 UTF-8 bytes.</exception>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="cost"/> is outside 10 to 16.</exception>
        public string HashPasswordWithParameters(string passToHash, uint cost = 12)
        {
            ValidatePassword(passToHash, nameof(passToHash));
            if (cost < MinCost || cost > MaxCost)
            {
                throw new ArgumentOutOfRangeException(nameof(cost), cost, $"The BCrypt cost must be between {MinCost} and {MaxCost}.");
            }

            byte[] passwordBytes = PasswordBytes.Encode(passToHash);
            try
            {
                fixed (byte* passPtr = passwordBytes)
                {
                    CasStringResult hashResult = NativeMethods.bcrypt_hash_with_parameters_bytes(passPtr, (nuint)passwordBytes.Length, cost);
                    CasErrorHandler.ThrowIfError(hashResult.error_code, "BCrypt hash");
                    return NativeString.ReadAndFree(hashResult.value);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(passwordBytes);
            }
        }

        /// <summary>
        /// Verifies a hashed password against an unhashed password using the BCrypt algorithm.
        /// </summary>
        /// <param name="hashedPassword">The stored bcrypt hash.</param>
        /// <param name="unhashed">The password to check: not null or empty, and at most 72 UTF-8 bytes (<see cref="MaxPasswordBytes"/>).</param>
        /// <exception cref="ArgumentNullException">An argument is null.</exception>
        /// <exception cref="ArgumentException">An argument is empty, or <paramref name="unhashed"/> is longer than 72 UTF-8 bytes.</exception>
        /// <exception cref="CasException">The hash can't be parsed, or its cost is above 16.</exception>
        public bool Verify(string hashedPassword, string unhashed)
        {
            if (hashedPassword == null)
            {
                throw new ArgumentNullException(nameof(hashedPassword));
            }
            if (hashedPassword.Length == 0)
            {
                throw new ArgumentException("The hashed password must not be empty.", nameof(hashedPassword));
            }
            ValidatePassword(unhashed, nameof(unhashed));

            byte[] passwordBytes = PasswordBytes.Encode(unhashed);
            try
            {
                fixed (byte* passPtr = passwordBytes)
                fixed (byte* hashPtr = NativeString.ToCString(hashedPassword))
                {
                    CasVerifyResult result = NativeMethods.bcrypt_verify_bytes(passPtr, (nuint)passwordBytes.Length, hashPtr);
                    CasErrorHandler.ThrowIfError(result.error_code, "BCrypt verify");
                    return result.is_valid;
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(passwordBytes);
            }
        }

        private static void ValidatePassword(string password, string paramName)
        {
            int byteCount = PasswordBytes.Validate(password, paramName);
            if (byteCount > MaxPasswordBytes)
            {
                throw new ArgumentException($"BCrypt passwords must be at most {MaxPasswordBytes} UTF-8 bytes; this one is {byteCount}.", paramName);
            }
        }
    }
}
