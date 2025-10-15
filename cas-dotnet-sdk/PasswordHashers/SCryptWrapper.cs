using CasDotnetSdk.Helpers;
using CasDotnetSdk.PasswordHashers.Linux;
using CasDotnetSdk.PasswordHashers.Windows;
using CASHelpers.Types.HttpResponses.BenchmarkAPI;
using System;
using System.Reflection;
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
        public string HashPassword(string passToHash)
        {
            if (string.IsNullOrEmpty(passToHash))
            {
                throw new Exception("Please provide a password to hash");
            }

            DateTime start = DateTime.UtcNow;
            IntPtr hashedPtr = (this._platform == OSPlatform.Linux) ? SCryptLinuxWrapper.scrypt_hash(passToHash) : SCryptWindowsWrapper.scrypt_hash(passToHash);
            string hashed = Marshal.PtrToStringAnsi(hashedPtr);
            FreeMemoryHelper.FreeCStringMemory(hashedPtr);
            DateTime end = DateTime.UtcNow;
            this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(SCryptWrapper));
            return hashed;
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

            DateTime start = DateTime.UtcNow;
            bool result = (this._platform == OSPlatform.Linux) ? SCryptLinuxWrapper.scrypt_verify(hashedPassword, password) : SCryptWindowsWrapper.scrypt_verify(hashedPassword, password);
            DateTime end = DateTime.UtcNow;
            this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(SCryptWrapper));
            return result;
        }
    }
}