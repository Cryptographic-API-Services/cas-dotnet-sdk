using CasCoreLib;
using CasDotnetSdk.Helpers;
using System;
using System.Security.Cryptography;

namespace CasDotnetSdk.PasswordHashers
{
    public unsafe class Argon2Wrapper : IPasswordHasherBase
    {
        /// <summary>The smallest <c>memoryCost</c> accepted, in MiB.</summary>
        public const int MinMemoryCostMiB = 19;
        /// <summary>The largest <c>memoryCost</c> accepted, in MiB (4 GiB).</summary>
        public const int MaxMemoryCostMiB = 4096;
        /// <summary>The smallest <c>iterations</c> accepted.</summary>
        public const int MinIterations = 1;
        /// <summary>The largest <c>iterations</c> accepted.</summary>
        public const int MaxIterations = 10;
        /// <summary>The smallest <c>parallelism</c> accepted.</summary>
        public const int MinParallelism = 1;
        /// <summary>The largest <c>parallelism</c> accepted.</summary>
        public const int MaxParallelism = 16;
        /// <summary>The shortest salt, in bytes, that the salted key derivation accepts. <see cref="GenerateSalt"/> returns this many bytes.</summary>
        public const int MinSaltLength = 16;

        /// <summary>
        /// A wrapper class for the Argon2 password hashing algorithm.
        /// </summary>
        public Argon2Wrapper()
        {
        }

        /// <summary>
        /// Hashes the specified password using Argon2id with the provided memory cost, iteration count, and
        /// parallelism parameters. The whole UTF-8 encoding of the password is hashed, including any <c>'\0'</c>.
        /// </summary>
        /// <param name="memoryCost">Memory to use, in MiB, from 19 (<see cref="MinMemoryCostMiB"/>) to 4096 (<see cref="MaxMemoryCostMiB"/>). <see cref="HashPassword"/> uses 19.</param>
        /// <param name="iterations">Number of passes over memory (time cost), from 1 to 10. <see cref="HashPassword"/> uses 2.</param>
        /// <param name="parallelism">Number of threads (lanes), from 1 to 16. <see cref="HashPassword"/> uses 1.</param>
        /// <param name="passToHash">The password to hash. Must not be null or empty.</param>
        /// <exception cref="ArgumentOutOfRangeException">A cost parameter is outside its range.</exception>
        /// <exception cref="ArgumentNullException"><paramref name="passToHash"/> is null.</exception>
        /// <exception cref="ArgumentException"><paramref name="passToHash"/> is empty.</exception>
        public string HashPasswordWithParameters(int memoryCost, int iterations, int parallelism, string passToHash)
        {
            if (memoryCost < MinMemoryCostMiB || memoryCost > MaxMemoryCostMiB)
            {
                throw new ArgumentOutOfRangeException(nameof(memoryCost), memoryCost, $"The Argon2 memory cost must be between {MinMemoryCostMiB} and {MaxMemoryCostMiB} MiB.");
            }
            if (iterations < MinIterations || iterations > MaxIterations)
            {
                throw new ArgumentOutOfRangeException(nameof(iterations), iterations, $"The Argon2 iteration count must be between {MinIterations} and {MaxIterations}.");
            }
            if (parallelism < MinParallelism || parallelism > MaxParallelism)
            {
                throw new ArgumentOutOfRangeException(nameof(parallelism), parallelism, $"The Argon2 parallelism must be between {MinParallelism} and {MaxParallelism}.");
            }
            PasswordBytes.Validate(passToHash, nameof(passToHash));

            byte[] passwordBytes = PasswordBytes.Encode(passToHash);
            try
            {
                fixed (byte* passPtr = passwordBytes)
                {
                    CasStringResult hashResult = NativeMethods.argon2_hash_password_parameters_bytes(checked((uint)memoryCost), checked((uint)iterations), checked((uint)parallelism), passPtr, (nuint)passwordBytes.Length);
                    CasErrorHandler.ThrowIfError(hashResult.error_code, "Argon2 hash");
                    return NativeString.ReadAndFree(hashResult.value);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(passwordBytes);
            }
        }

        /// <summary>
        /// Hashes a password using Argon2id with the default parameters (19 MiB, 2 iterations, parallelism 1).
        /// The whole UTF-8 encoding of the password is hashed, including any <c>'\0'</c>.
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
                    CasStringResult hashResult = NativeMethods.argon2_hash_bytes(passPtr, (nuint)passwordBytes.Length);
                    CasErrorHandler.ThrowIfError(hashResult.error_code, "Argon2 hash");
                    return NativeString.ReadAndFree(hashResult.value);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(passwordBytes);
            }
        }

        /// <summary>
        /// Verifies that a password matches an Argon2 hash.
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
                fixed (byte* hashedPtr = NativeString.ToCString(hashedPassword))
                fixed (byte* passwordPtr = passwordBytes)
                {
                    CasVerifyResult result = NativeMethods.argon2_verify_bytes(hashedPtr, passwordPtr, (nuint)passwordBytes.Length);
                    CasErrorHandler.ThrowIfError(result.error_code, "Argon2 verify");
                    return result.is_valid;
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(passwordBytes);
            }
        }

        /// <summary>
        /// Generates a random 16-byte salt for <see cref="DeriveAES256Key(string, byte[])"/> and
        /// <see cref="DeriveAES128Key(string, byte[])"/>. The salt is not secret: store it next to whatever
        /// the key protects and pass it back with the same password to re-derive the same key.
        /// </summary>
        public byte[] GenerateSalt()
        {
            Argon2Salt result = NativeMethods.argon2_generate_salt();
            CasErrorHandler.ThrowIfError(result.error_code, "Argon2 generate salt");
            return NativeByteBuffer.CopyAndFree(result.salt, result.length);
        }

        /// <summary>
        /// Derives a 32-byte AES-256 key from a password and salt with Argon2id (19 MiB, 2 iterations,
        /// parallelism 1). The same password and salt always give the same key.
        /// </summary>
        /// <param name="password">The password. Must not be null or empty.</param>
        /// <param name="salt">At least 16 bytes (<see cref="MinSaltLength"/>), usually from <see cref="GenerateSalt"/>.</param>
        /// <exception cref="ArgumentNullException">An argument is null.</exception>
        /// <exception cref="ArgumentException"><paramref name="password"/> is empty, or <paramref name="salt"/> is shorter than 16 bytes.</exception>
        public byte[] DeriveAES256Key(string password, byte[] salt)
        {
            PasswordBytes.Validate(password, nameof(password));
            ValidateSalt(salt);

            byte[] passwordBytes = PasswordBytes.Encode(password);
            try
            {
                fixed (byte* passwordPtr = passwordBytes)
                fixed (byte* saltPtr = salt)
                {
                    Argon2DerivedKey kdfResult = NativeMethods.argon2_derive_aes_256_key_with_salt(passwordPtr, (nuint)passwordBytes.Length, saltPtr, (nuint)salt.Length);
                    CasErrorHandler.ThrowIfError(kdfResult.error_code, "Argon2 derive AES-256 key");
                    return NativeByteBuffer.CopyAndFree(kdfResult.key, kdfResult.length);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(passwordBytes);
            }
        }

        /// <summary>
        /// Derives a 16-byte AES-128 key from a password and salt with Argon2id (19 MiB, 2 iterations,
        /// parallelism 1). The same password and salt always give the same key.
        /// </summary>
        /// <param name="password">The password. Must not be null or empty.</param>
        /// <param name="salt">At least 16 bytes (<see cref="MinSaltLength"/>), usually from <see cref="GenerateSalt"/>.</param>
        /// <exception cref="ArgumentNullException">An argument is null.</exception>
        /// <exception cref="ArgumentException"><paramref name="password"/> is empty, or <paramref name="salt"/> is shorter than 16 bytes.</exception>
        public byte[] DeriveAES128Key(string password, byte[] salt)
        {
            PasswordBytes.Validate(password, nameof(password));
            ValidateSalt(salt);

            byte[] passwordBytes = PasswordBytes.Encode(password);
            try
            {
                fixed (byte* passwordPtr = passwordBytes)
                fixed (byte* saltPtr = salt)
                {
                    Argon2DerivedKey kdfResult = NativeMethods.argon2_derive_aes_128_key_with_salt(passwordPtr, (nuint)passwordBytes.Length, saltPtr, (nuint)salt.Length);
                    CasErrorHandler.ThrowIfError(kdfResult.error_code, "Argon2 derive AES-128 key");
                    return NativeByteBuffer.CopyAndFree(kdfResult.key, kdfResult.length);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(passwordBytes);
            }
        }

        /// <summary>
        /// Derives a 32-byte AES-256 key from the password with a random salt that is thrown away, so the
        /// same password never gives the same key again and the key can't be re-derived to decrypt later.
        /// Use <see cref="GenerateSalt"/> and <see cref="DeriveAES256Key(string, byte[])"/> instead.
        /// </summary>
        /// <exception cref="ArgumentNullException"><paramref name="password"/> is null.</exception>
        /// <exception cref="ArgumentException"><paramref name="password"/> is empty.</exception>
        [Obsolete("The salt is discarded, so the key can't be re-derived. Use GenerateSalt() and DeriveAES256Key(string password, byte[] salt), and store the salt.")]
        public byte[] DeriveAES256Key(string password)
        {
            return DeriveAES256Key(password, GenerateSalt());
        }

        /// <summary>
        /// Derives a 16-byte AES-128 key from the password with a random salt that is thrown away, so the
        /// same password never gives the same key again and the key can't be re-derived to decrypt later.
        /// Use <see cref="GenerateSalt"/> and <see cref="DeriveAES128Key(string, byte[])"/> instead.
        /// </summary>
        /// <exception cref="ArgumentNullException"><paramref name="password"/> is null.</exception>
        /// <exception cref="ArgumentException"><paramref name="password"/> is empty.</exception>
        [Obsolete("The salt is discarded, so the key can't be re-derived. Use GenerateSalt() and DeriveAES128Key(string password, byte[] salt), and store the salt.")]
        public byte[] DeriveAES128Key(string password)
        {
            return DeriveAES128Key(password, GenerateSalt());
        }

        private static void ValidateSalt(byte[] salt)
        {
            if (salt == null)
            {
                throw new ArgumentNullException(nameof(salt));
            }
            if (salt.Length < MinSaltLength)
            {
                throw new ArgumentException($"The salt must be at least {MinSaltLength} bytes.", nameof(salt));
            }
        }
    }
}
