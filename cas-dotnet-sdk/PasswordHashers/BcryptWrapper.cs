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
        public BcryptWrapper()
        {
            this._platform = new OperatingSystemDeterminator().GetOperatingSystem();
            this._benchmarkSender = new BenchmarkSender();
        }

        public string HashPassword(string passwordToHash)
        {

            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                IntPtr hashedPtr = BcryptLinuxWrapper.bcrypt_hash(passwordToHash);
                string hashed = Marshal.PtrToStringAnsi(hashedPtr);
                BcryptLinuxWrapper.free_cstring(hashedPtr);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(BcryptWrapper));
                return hashed;
            }
            else
            {
                IntPtr hashedPtr = BcryptWindowsWrapper.bcrypt_hash(passwordToHash);
                string hashed = Marshal.PtrToStringAnsi(hashedPtr);
                BcryptWindowsWrapper.free_cstring(hashedPtr);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(BcryptWrapper));
                return hashed;
            }
        }

        public string[] HashPasswordsThread(string[] passwordsToHash)
        {
            throw new NotImplementedException();
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
                BcryptLinuxWrapper.free_cstring(hashedPtr);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(BcryptWrapper));
                return hashed;
            }
            else
            {
                IntPtr hashedPtr = BcryptWindowsWrapper.bcrypt_hash_threadpool(password);
                string hashed = Marshal.PtrToStringAnsi(hashedPtr);
                BcryptWindowsWrapper.free_cstring(hashedPtr);
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

        public bool VerifyPasswordThread(string hashedPasswrod, string password)
        {
            throw new NotImplementedException();
        }
    }
}