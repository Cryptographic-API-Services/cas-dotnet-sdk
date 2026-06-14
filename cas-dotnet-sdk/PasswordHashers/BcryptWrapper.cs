
using CasDotnetSdk.Helpers;
using CasDotnetSdk.Helpers.Types;
using CasDotnetSdk.PasswordHashers.Linux;
using CasDotnetSdk.PasswordHashers.Windows;
using System;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.PasswordHashers
{
    public class BcryptWrapper : BaseWrapper, IPasswordHasherBase
    {

        /// <summary>
        /// A wrapper class that uses the BCrypt algorithm to hash passwords.
        /// </summary>
        public BcryptWrapper()
        {

        }

        /// <summary>
        /// Hashes a password using the BCrypt algorithm.
        /// </summary>
        /// <param name="passwordToHash"></param>
        /// <returns></returns>
        /// 

        public string HashPassword(string passwordToHash)
        {


            CasStringResult hashResult = (this._platform == OSPlatform.Linux) ?
                BcryptLinuxWrapper.bcrypt_hash(passwordToHash) :
                BcryptWindowsWrapper.bcrypt_hash(passwordToHash);
            CasErrorHandler.ThrowIfError(hashResult.error_code, "BCrypt hash");
            string hashed = Marshal.PtrToStringAnsi(hashResult.value);
            FreeMemoryHelper.FreeCStringMemory(hashResult.value);
            return hashed;
        }
        /// <summary>
        /// Hashes a password using the BCrypt algorithm with specified parameters.
        /// Max cost is 31.
        /// </summary>
        /// <param name="passToHash"></param>
        /// <param name="cost"></param>
        /// <returns></returns>


        public string HashPasswordWithParameters(string passToHash, uint cost = 12)
        {
            CasStringResult hashResult = (this._platform == OSPlatform.Linux) ?
                BcryptLinuxWrapper.bcrypt_hash_with_parameters(passToHash, cost) :
                BcryptWindowsWrapper.bcrypt_hash_with_parameters(passToHash, cost);
            CasErrorHandler.ThrowIfError(hashResult.error_code, "BCrypt hash");
            string hashed = Marshal.PtrToStringAnsi(hashResult.value);
            FreeMemoryHelper.FreeCStringMemory(hashResult.value);
            return hashed;
        }

        /// <summary>
        /// Verifies a hashed password against an unhashed password using the BCrypt algorithm.
        /// </summary>
        /// <param name="hashedPassword"></param>
        /// <param name="unhashed"></param>
        /// <returns></returns>
        /// 

        public bool Verify(string hashedPassword, string unhashed)
        {

            CasVerifyResult result = (this._platform == OSPlatform.Linux) ?
                BcryptLinuxWrapper.bcrypt_verify(unhashed, hashedPassword) :
                BcryptWindowsWrapper.bcrypt_verify(unhashed, hashedPassword); ;
            CasErrorHandler.ThrowIfError(result.error_code, "BCrypt verify");


            return result.is_valid;
        }
    }
}