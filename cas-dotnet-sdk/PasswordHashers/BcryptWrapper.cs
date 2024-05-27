using CasDotnetSdk.Helpers;
using CasDotnetSdk.Http;
using CasDotnetSdk.PasswordHashers.Linux;
using CasDotnetSdk.PasswordHashers.Windows;
using CASHelpers;
using CASHelpers.Types.HttpResponses.BenchmarkAPI;
using System;
using System.Reflection;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.PasswordHashers
{
    public class BcryptWrapper : IPasswordHasherBase
    {
        private readonly OSPlatform _platform;
        private readonly BenchmarkSender _benchmarkSender;

        /// <summary>
        /// A wrapper class that uses the BCrypt algorithm to hash passwords.
        /// </summary>
        public BcryptWrapper()
        {
            this._platform = new OperatingSystemDeterminator().GetOperatingSystem();
            this._benchmarkSender = new BenchmarkSender();
        }

        /// <summary>
        /// Hashes a password using the BCrypt algorithm.
        /// </summary>
        /// <param name="passwordToHash"></param>
        /// <returns></returns>
        public string HashPassword(string passwordToHash)
        {

            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                IntPtr hashedPtr = BcryptLinuxWrapper.bcrypt_hash(passwordToHash);
                string hashed = Marshal.PtrToStringAnsi(hashedPtr);
                FreeMemoryHelper.FreeCStringMemory(hashedPtr);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(BcryptWrapper));
                return hashed;
            }
            else
            {
                IntPtr hashedPtr = BcryptWindowsWrapper.bcrypt_hash(passwordToHash);
                string hashed = Marshal.PtrToStringAnsi(hashedPtr);
                FreeMemoryHelper.FreeCStringMemory(hashedPtr);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(BcryptWrapper));
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
            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                IntPtr hashedPtr = BcryptLinuxWrapper.bcrypt_hash_threadpool(password);
                string hashed = Marshal.PtrToStringAnsi(hashedPtr);
                FreeMemoryHelper.FreeCStringMemory(hashedPtr);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(BcryptWrapper));
                return hashed;
            }
            else
            {
                IntPtr hashedPtr = BcryptWindowsWrapper.bcrypt_hash_threadpool(password);
                string hashed = Marshal.PtrToStringAnsi(hashedPtr);
                FreeMemoryHelper.FreeCStringMemory(hashedPtr);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(BcryptWrapper));
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
            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                bool result = BcryptLinuxWrapper.bcrypt_verify(unhashed, hashedPassword);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(BcryptWrapper));
                return result;
            }
            else
            {
                bool result = BcryptWindowsWrapper.bcrypt_verify(unhashed, hashedPassword);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(BcryptWrapper));
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
            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                bool result = BcryptLinuxWrapper.bcrypt_verify_threadpool(verifyPassword, hashedPassword);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(BcryptWrapper));
                return result;
            }
            else
            {
                bool result = BcryptWindowsWrapper.bcrypt_verify_threadpool(verifyPassword, hashedPassword);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(BcryptWrapper));
                return result;
            }
        }
    }
}