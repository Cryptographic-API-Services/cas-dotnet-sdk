using System;
using System.Runtime.InteropServices;
using CasDotnetSdk.Helpers;
using CasDotnetSdk.PasswordHashers.Linux;
using CasDotnetSdk.PasswordHashers.Windows;

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
        public string HashPassword(string passToHash)
        {
            if (string.IsNullOrEmpty(passToHash))
            {
                throw new Exception("Please provide a password to hash");
            }


            if (this._platform == OSPlatform.Linux)
            {
                IntPtr hashedPtr = SCryptLinuxWrapper.scrypt_hash(passToHash);
                string hashed = Marshal.PtrToStringAnsi(hashedPtr);
                FreeMemoryHelper.FreeCStringMemory(hashedPtr);


                return hashed;
            }
            else
            {
                IntPtr hashedPtr = SCryptWindowsWrapper.scrypt_hash(passToHash);
                string hashed = Marshal.PtrToStringAnsi(hashedPtr);
                FreeMemoryHelper.FreeCStringMemory(hashedPtr);


                return hashed;
            }
        }

        /// <summary>
        /// Hashes the password using the SCrypt algorithm in a separate thread.
        /// </summary>
        /// <param name="password"></param>
        /// <returns></returns>
        public string HashPasswordThreadPool(string password)
        {
            if (!CASConfiguration.IsThreadingEnabled)
            {
                throw new Exception("You do not have the product subscription to work with the thread pool featues");
            }

            if (string.IsNullOrEmpty(password))
            {
                throw new Exception("Please provide a password to hash");
            }


            if (this._platform == OSPlatform.Linux)
            {
                IntPtr hashedPtr = SCryptLinuxWrapper.scrypt_hash_threadpool(password);
                string hashed = Marshal.PtrToStringAnsi(hashedPtr);
                FreeMemoryHelper.FreeCStringMemory(hashedPtr);


                return hashed;
            }
            else
            {
                IntPtr hashedPtr = SCryptWindowsWrapper.scrypt_hash_threadpool(password);
                string hashed = Marshal.PtrToStringAnsi(hashedPtr);
                FreeMemoryHelper.FreeCStringMemory(hashedPtr);


                return hashed;
            }
        }

        /// <summary>
        /// Verifies an unhashed password against a hashed password using the SCrypt algorithm.
        /// </summary>
        /// <param name="password"></param>
        /// <param name="hash"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public bool Verify(string hashedPassword, string password)
        {
            if (string.IsNullOrEmpty(password) || string.IsNullOrEmpty(hashedPassword))
            {
                throw new Exception("Please provide a password and a hash to verify");
            }


            if (this._platform == OSPlatform.Linux)
            {
                bool result = SCryptLinuxWrapper.scrypt_verify(hashedPassword, password);


                return result;
            }
            else
            {

                bool result = SCryptWindowsWrapper.scrypt_verify(hashedPassword, password);


                return result;
            }
        }

        /// <summary>
        /// Verifies an unhashed password against a hashed password using the SCrypt algorithm in a separate thread.
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

            if (string.IsNullOrEmpty(hashedPassword) || string.IsNullOrEmpty(verifyPassword))
            {
                throw new Exception("Please provide a password and a hash to verify");
            }


            if (this._platform == OSPlatform.Linux)
            {
                bool result = SCryptLinuxWrapper.scrypt_verify_threadpool(verifyPassword, hashedPassword);


                return result;
            }
            else
            {
                bool result = SCryptWindowsWrapper.scrypt_verify_threadpool(verifyPassword, hashedPassword);


                return result;
            }
        }
    }
}