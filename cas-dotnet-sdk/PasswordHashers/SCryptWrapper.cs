using CasCoreLib;
using CasDotnetSdk.Helpers;
using System;

namespace CasDotnetSdk.PasswordHashers
{
    public unsafe class SCryptWrapper : IPasswordHasherBase
    {
        /// <summary>
        /// A wrapper class that uses the SCrypt algorithm to hash passwords.
        /// </summary>
        public SCryptWrapper()
        {
        }

        /// <summary>
        /// Hashes a password using the SCrypt algorithm.
        /// </summary>
        public string HashPassword(string passToHash)
        {
            if (string.IsNullOrEmpty(passToHash))
            {
                throw new Exception("Please provide a password to hash");
            }

            fixed (byte* passPtr = NativeString.ToCString(passToHash))
            {
                CasStringResult hashResult = NativeMethods.scrypt_hash(passPtr);
                CasErrorHandler.ThrowIfError(hashResult.error_code, "SCrypt hash");
                return NativeString.ReadAndFree(hashResult.value);
            }
        }

        public string HashPasswordWithParameters(string passToHash, int cpuCost = 17, int blockSize = 8, int parallelism = 1)
        {
            if (string.IsNullOrEmpty(passToHash))
            {
                throw new Exception("Please provide a password to hash");
            }

            fixed (byte* passPtr = NativeString.ToCString(passToHash))
            {
                CasStringResult hashResult = NativeMethods.scrypt_hash_with_parameters(passPtr, (byte)cpuCost, (uint)blockSize, (uint)parallelism);
                CasErrorHandler.ThrowIfError(hashResult.error_code, "SCrypt hash");
                return NativeString.ReadAndFree(hashResult.value);
            }
        }

        /// <summary>
        /// Verifies an unhashed password against a hashed password using the SCrypt algorithm.
        /// </summary>
        public bool Verify(string hashedPassword, string password)
        {
            if (string.IsNullOrEmpty(password) || string.IsNullOrEmpty(hashedPassword))
            {
                throw new Exception("Please provide a password and a hash to verify");
            }

            fixed (byte* hashPtr = NativeString.ToCString(hashedPassword))
            fixed (byte* passPtr = NativeString.ToCString(password))
            {
                CasVerifyResult result = NativeMethods.scrypt_verify(hashPtr, passPtr);
                CasErrorHandler.ThrowIfError(result.error_code, "SCrypt verify");
                return result.is_valid;
            }
        }
    }
}
