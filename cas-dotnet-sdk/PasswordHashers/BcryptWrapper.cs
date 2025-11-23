using CasDotnetSdk.Fodies;
using CasDotnetSdk.Helpers;
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
        [BenchmarkSender]
        public string HashPassword(string passwordToHash)
        {

            
            IntPtr hashedPtr = (this._platform == OSPlatform.Linux) ?
                BcryptLinuxWrapper.bcrypt_hash(passwordToHash) :
                BcryptWindowsWrapper.bcrypt_hash(passwordToHash);
            string hashed = Marshal.PtrToStringAnsi(hashedPtr);
            FreeMemoryHelper.FreeCStringMemory(hashedPtr);
            

            return hashed;
        }

        /// <summary>
        /// Verifies a hashed password against an unhashed password using the BCrypt algorithm.
        /// </summary>
        /// <param name="hashedPassword"></param>
        /// <param name="unhashed"></param>
        /// <returns></returns>
        /// 
        [BenchmarkSender]
        public bool Verify(string hashedPassword, string unhashed)
        {
            
            bool result = (this._platform == OSPlatform.Linux) ?
                BcryptLinuxWrapper.bcrypt_verify(unhashed, hashedPassword) :
                BcryptWindowsWrapper.bcrypt_verify(unhashed, hashedPassword); ;
            

            return result;
        }
    }
}