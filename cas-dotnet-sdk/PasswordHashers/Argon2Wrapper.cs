using System;
using System.Runtime.InteropServices;
using CasDotnetSdk.Helpers;
using CasDotnetSdk.PasswordHashers.Linux;
using CasDotnetSdk.PasswordHashers.Types;
using CasDotnetSdk.PasswordHashers.Windows;

namespace CasDotnetSdk.PasswordHashers
{
    public class Argon2Wrapper : BaseWrapper, IPasswordHasherBase
    {

        /// <summary>
        /// A wrapper class for the Argon2 password hashing algorithm.
        /// </summary>
        public Argon2Wrapper()
        {
        }
        /// <summary>
        /// Hashes a password using the Argon2 algorithm.
        /// </summary>
        /// <param name="passToHash"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public string HashPassword(string passToHash)
        {
            if (string.IsNullOrEmpty(passToHash))
            {
                throw new Exception("You must provide a password to hash using argon2");
            }


            if (this._platform == OSPlatform.Linux)
            {
                IntPtr hashedPtr = Argon2LinuxWrapper.argon2_hash(passToHash);
                string hashed = Marshal.PtrToStringAnsi(hashedPtr);
                FreeMemoryHelper.FreeCStringMemory(hashedPtr);


                return hashed;
            }
            else
            {
                IntPtr hashedPtr = Argon2WindowsWrapper.argon2_hash(passToHash);
                string hashed = Marshal.PtrToStringAnsi(hashedPtr);
                FreeMemoryHelper.FreeCStringMemory(hashedPtr);


                return hashed;
            }
        }

        /// <summary>
        /// Verifies that a none hahsed password matches the hashed password using Argon2 algorithm.
        /// </summary>
        /// <param name="hashedPasswrod"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public bool Verify(string hashedPasswrod, string password)
        {
            if (string.IsNullOrEmpty(hashedPasswrod) || string.IsNullOrEmpty(password))
            {
                throw new Exception("You must provide a hashed password and password to verify with argon2");
            }


            if (this._platform == OSPlatform.Linux)
            {

                bool result = Argon2LinuxWrapper.argon2_verify(hashedPasswrod, password);


                return result;
            }
            else
            {
                bool result = Argon2WindowsWrapper.argon2_verify(hashedPasswrod, password);


                return result;
            }
        }

        /// <summary>
        /// Hashes a password using Argon2 on a seperate thread
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
                throw new Exception("You must provide a password to hash using argon2");
            }


            if (this._platform == OSPlatform.Linux)
            {
                IntPtr hashedPtr = Argon2LinuxWrapper.argon2_hash_threadpool(password);
                string hashed = Marshal.PtrToStringAnsi(hashedPtr);
                FreeMemoryHelper.FreeCStringMemory(hashedPtr);


                return hashed;
            }
            else
            {
                IntPtr hashedPtr = Argon2WindowsWrapper.argon2_hash_threadpool(password);
                string hashed = Marshal.PtrToStringAnsi(hashedPtr);
                FreeMemoryHelper.FreeCStringMemory(hashedPtr);


                return hashed;
            }
        }

        /// <summary>
        /// Verifies a password using Argon2 on a seperate thread
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
                throw new Exception("You must provide a hashed password and password to verify with argon2");
            }


            if (this._platform == OSPlatform.Linux)
            {

                bool result = Argon2LinuxWrapper.argon2_verify_threadpool(hashedPassword, verifyPassword);


                return result;
            }
            else
            {
                bool result = Argon2WindowsWrapper.argon2_verify_threadpool(hashedPassword, verifyPassword);


                return result;
            }
        }

        /// <summary>
        /// Derives an 32-byte AES256 key based off the password passed in using Argon2.
        /// </summary>
        /// <param name="password"></param>
        /// <returns></returns>
        public byte[] DeriveAES256Key(string password)
        {

            if (this._platform == OSPlatform.Linux)
            {
                Argon2KDFResult kdfResult = Argon2LinuxWrapper.argon2_derive_aes_256_key(password);
                byte[] result = new byte[kdfResult.length];
                Marshal.Copy(kdfResult.key, result, 0, kdfResult.length);
                FreeMemoryHelper.FreeBytesMemory(kdfResult.key);


                return result;
            }
            else
            {
                Argon2KDFResult kdfResult = Argon2WindowsWrapper.argon2_derive_aes_256_key(password);
                byte[] result = new byte[kdfResult.length];
                Marshal.Copy(kdfResult.key, result, 0, kdfResult.length);
                FreeMemoryHelper.FreeBytesMemory(kdfResult.key);


                return result;
            }
        }

        /// <summary>
        /// Derives an 16-byte AES128 key based off the password passed in using Argon2.
        /// </summary>
        /// <param name="password"></param>
        /// <returns></returns>
        public byte[] DeriveAES128Key(string password)
        {

            if (this._platform == OSPlatform.Linux)
            {
                Argon2KDFResult kdfResult = Argon2LinuxWrapper.argon2_derive_aes_128_key(password);
                byte[] result = new byte[kdfResult.length];
                Marshal.Copy(kdfResult.key, result, 0, kdfResult.length);
                FreeMemoryHelper.FreeBytesMemory(kdfResult.key);


                return result;
            }
            else
            {
                Argon2KDFResult kdfResult = Argon2WindowsWrapper.argon2_derive_aes_128_key(password);
                byte[] result = new byte[kdfResult.length];
                Marshal.Copy(kdfResult.key, result, 0, kdfResult.length);
                FreeMemoryHelper.FreeBytesMemory(kdfResult.key);


                return result;
            }
        }
    }
}
