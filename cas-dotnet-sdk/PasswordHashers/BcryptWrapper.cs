using System;
using System.Runtime.InteropServices;
using CasDotnetSdk.Helpers;
using CasDotnetSdk.PasswordHashers.Linux;
using CasDotnetSdk.PasswordHashers.Windows;

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
        public string HashPassword(string passwordToHash)
        {


            if (this._platform == OSPlatform.Linux)
            {
                IntPtr hashedPtr = BcryptLinuxWrapper.bcrypt_hash(passwordToHash);
                string hashed = Marshal.PtrToStringAnsi(hashedPtr);
                FreeMemoryHelper.FreeCStringMemory(hashedPtr);


                return hashed;
            }
            else
            {
                IntPtr hashedPtr = BcryptWindowsWrapper.bcrypt_hash(passwordToHash);
                string hashed = Marshal.PtrToStringAnsi(hashedPtr);
                FreeMemoryHelper.FreeCStringMemory(hashedPtr);


                return hashed;
            }
        }

        /// <summary>
        /// Hashes a password using the BCrypt algorithm on a new thread.
        /// </summary>
        /// <param name="password"></param>
        /// <returns></returns>
        public string HashPasswordThreadPool(string password)
        {
            if (!CASConfiguration.IsThreadingEnabled)
            {
                throw new Exception("You do not have the product subscription to work with the thread pool featues");
            }


            if (this._platform == OSPlatform.Linux)
            {
                IntPtr hashedPtr = BcryptLinuxWrapper.bcrypt_hash_threadpool(password);
                string hashed = Marshal.PtrToStringAnsi(hashedPtr);
                FreeMemoryHelper.FreeCStringMemory(hashedPtr);


                return hashed;
            }
            else
            {
                IntPtr hashedPtr = BcryptWindowsWrapper.bcrypt_hash_threadpool(password);
                string hashed = Marshal.PtrToStringAnsi(hashedPtr);
                FreeMemoryHelper.FreeCStringMemory(hashedPtr);


                return hashed;
            }
        }

        /// <summary>
        /// Verifies a hashed password against an unhashed password using the BCrypt algorithm.
        /// </summary>
        /// <param name="hashedPassword"></param>
        /// <param name="unhashed"></param>
        /// <returns></returns>
        public bool Verify(string hashedPassword, string unhashed)
        {

            if (this._platform == OSPlatform.Linux)
            {
                bool result = BcryptLinuxWrapper.bcrypt_verify(unhashed, hashedPassword);


                return result;
            }
            else
            {
                bool result = BcryptWindowsWrapper.bcrypt_verify(unhashed, hashedPassword);


                return result;
            }
        }

        /// <summary>
        /// Verifies a hashed password against an unhashed password using the BCrypt algorithm on a new thread.
        /// </summary>
        /// <param name="hashedPassword"></param>
        /// <param name="verifyPassword"></param>
        /// <returns></returns>

        public bool VerifyThreadPool(string hashedPassword, string verifyPassword)
        {
            if (!CASConfiguration.IsThreadingEnabled)
            {
                throw new Exception("You do not have the product subscription to work with the thread pool featues");
            }


            if (this._platform == OSPlatform.Linux)
            {
                bool result = BcryptLinuxWrapper.bcrypt_verify_threadpool(verifyPassword, hashedPassword);


                return result;
            }
            else
            {
                bool result = BcryptWindowsWrapper.bcrypt_verify_threadpool(verifyPassword, hashedPassword);


                return result;
            }
        }
    }
}