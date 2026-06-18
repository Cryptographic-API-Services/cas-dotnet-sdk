using CasCoreLib;
using CasDotnetSdk.Helpers;
using System;

namespace CasDotnetSdk.PasswordHashers
{
    public unsafe class Argon2Wrapper : IPasswordHasherBase
    {
        /// <summary>
        /// A wrapper class for the Argon2 password hashing algorithm.
        /// </summary>
        public Argon2Wrapper()
        {
        }

        /// <summary>
        /// Hashes the specified password using the Argon2 algorithm with the provided memory cost, iteration count, and
        /// parallelism parameters.
        /// </summary>
        public string HashPasswordWithParameters(int memoryCost, int iterations, int parallelism, string passToHash)
        {
            if (string.IsNullOrEmpty(passToHash))
            {
                throw new Exception("You must provide a password to hash using argon2");
            }

            fixed (byte* passPtr = NativeString.ToCString(passToHash))
            {
                CasStringResult hashResult = NativeMethods.argon2_hash_password_parameters((uint)memoryCost, (uint)iterations, (uint)parallelism, passPtr);
                CasErrorHandler.ThrowIfError(hashResult.error_code, "Argon2 hash");
                return NativeString.ReadAndFree(hashResult.value);
            }
        }

        /// <summary>
        /// Hashes a password using the Argon2 algorithm.
        /// </summary>
        public string HashPassword(string passToHash)
        {
            if (string.IsNullOrEmpty(passToHash))
            {
                throw new Exception("You must provide a password to hash using argon2");
            }

            fixed (byte* passPtr = NativeString.ToCString(passToHash))
            {
                CasStringResult hashResult = NativeMethods.argon2_hash(passPtr);
                CasErrorHandler.ThrowIfError(hashResult.error_code, "Argon2 hash");
                return NativeString.ReadAndFree(hashResult.value);
            }
        }

        /// <summary>
        /// Verifies that a none hahsed password matches the hashed password using Argon2 algorithm.
        /// </summary>
        public bool Verify(string hashedPasswrod, string password)
        {
            if (string.IsNullOrEmpty(hashedPasswrod) || string.IsNullOrEmpty(password))
            {
                throw new Exception("You must provide a hashed password and password to verify with argon2");
            }

            fixed (byte* hashedPtr = NativeString.ToCString(hashedPasswrod))
            fixed (byte* passwordPtr = NativeString.ToCString(password))
            {
                CasVerifyResult result = NativeMethods.argon2_verify(hashedPtr, passwordPtr);
                CasErrorHandler.ThrowIfError(result.error_code, "Argon2 verify");
                return result.is_valid;
            }
        }

        /// <summary>
        /// Derives an 32-byte AES256 key based off the password passed in using Argon2.
        /// </summary>
        public byte[] DeriveAES256Key(string password)
        {
            fixed (byte* passwordPtr = NativeString.ToCString(password))
            {
                Argon2KDFAes128 kdfResult = NativeMethods.argon2_derive_aes_256_key(passwordPtr);
                CasErrorHandler.ThrowIfError(kdfResult.error_code, "Argon2 derive AES-256 key");
                return NativeByteBuffer.CopyAndFree(kdfResult.key, kdfResult.length);
            }
        }

        /// <summary>
        /// Derives an 16-byte AES128 key based off the password passed in using Argon2.
        /// </summary>
        public byte[] DeriveAES128Key(string password)
        {
            fixed (byte* passwordPtr = NativeString.ToCString(password))
            {
                Argon2KDFAes128 kdfResult = NativeMethods.argon2_derive_aes_128_key(passwordPtr);
                CasErrorHandler.ThrowIfError(kdfResult.error_code, "Argon2 derive AES-128 key");
                return NativeByteBuffer.CopyAndFree(kdfResult.key, kdfResult.length);
            }
        }
    }
}
