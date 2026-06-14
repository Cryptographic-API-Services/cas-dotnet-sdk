
using CasDotnetSdk.Helpers;
using CasDotnetSdk.Helpers.Types;
using CasDotnetSdk.PasswordHashers.Linux;
using CasDotnetSdk.PasswordHashers.Windows;
using System;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.PasswordHashers
{
    public class SCryptWrapper : BaseWrapper, IPasswordHasherBase
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
        /// <param name="passToHash"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        /// 

        public string HashPassword(string passToHash)
        {
            if (string.IsNullOrEmpty(passToHash))
            {
                throw new Exception("Please provide a password to hash");
            }

            CasStringResult hashResult = (this._platform == OSPlatform.Linux) ? SCryptLinuxWrapper.scrypt_hash(passToHash) : SCryptWindowsWrapper.scrypt_hash(passToHash);
            CasErrorHandler.ThrowIfError(hashResult.error_code, "SCrypt hash");
            string hashed = Marshal.PtrToStringAnsi(hashResult.value);
            FreeMemoryHelper.FreeCStringMemory(hashResult.value);
            return hashed;
        }


        public string HashPasswordWithParameters(string passToHash, int cpuCost = 17, int blockSize = 8, int parallelism = 1)
        {
            if (string.IsNullOrEmpty(passToHash))
            {
                throw new Exception("Please provide a password to hash");
            }

            CasStringResult hashResult = (this._platform == OSPlatform.Linux) ? SCryptLinuxWrapper.scrypt_hash_with_parameters(passToHash, cpuCost, blockSize, parallelism) : SCryptWindowsWrapper.scrypt_hash_with_parameters(passToHash, cpuCost, blockSize, parallelism);
            CasErrorHandler.ThrowIfError(hashResult.error_code, "SCrypt hash");
            string hashed = Marshal.PtrToStringAnsi(hashResult.value);
            FreeMemoryHelper.FreeCStringMemory(hashResult.value);
            return hashed;
        }

        /// <summary>
        /// Verifies an unhashed password against a hashed password using the SCrypt algorithm.
        /// </summary>
        /// <param name="password"></param>
        /// <param name="hash"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        /// 

        public bool Verify(string hashedPassword, string password)
        {
            if (string.IsNullOrEmpty(password) || string.IsNullOrEmpty(hashedPassword))
            {
                throw new Exception("Please provide a password and a hash to verify");
            }


            CasVerifyResult result = (this._platform == OSPlatform.Linux) ? SCryptLinuxWrapper.scrypt_verify(hashedPassword, password) : SCryptWindowsWrapper.scrypt_verify(hashedPassword, password);
            CasErrorHandler.ThrowIfError(result.error_code, "SCrypt verify");


            return result.is_valid;
        }
    }
}