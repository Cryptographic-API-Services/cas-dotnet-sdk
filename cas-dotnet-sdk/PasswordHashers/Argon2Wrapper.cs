using CasDotnetSdk.Http;
using CasDotnetSdk.PasswordHashers.Linux;
using CasDotnetSdk.PasswordHashers.Types;
using CasDotnetSdk.PasswordHashers.Windows;
using CASHelpers;
using CASHelpers.Types.HttpResponses.BenchmarkAPI;
using System;
using System.Collections.Generic;
using System.Reflection;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.PasswordHashers
{
    public class Argon2Wrapper : IPasswordHasherBase
    {
        private readonly OSPlatform _platform;
        private readonly BenchmarkSender _sender;

        /// <summary>
        /// A wrapper class for the Argon2 password hashing algorithm.
        /// </summary>
        public Argon2Wrapper()
        {
            this._platform = new OperatingSystemDeterminator().GetOperatingSystem();
            this._sender = new BenchmarkSender();
        }

        /// <summary>
        /// Hashes a list of passwords using the Argon2 algorithm.
        /// </summary>
        /// <param name="passwordsToHash"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public string[] HashPasswordsThread(string[] passwordsToHash)
        {
            if (passwordsToHash == null || passwordsToHash.Length <= 0)
            {
                throw new Exception("You must provide a list of passwords to hash using argon2");
            }

            DateTime start = DateTime.UtcNow;
            List<string> result = new List<string>();
            if (this._platform == OSPlatform.Linux)
            {
                Argon2ThreadResult hashedPasswordPtr = Argon2LinuxWrapper.argon2_hash_thread(passwordsToHash, passwordsToHash.Length);
                nint[] hashedResult = new nint[hashedPasswordPtr.length];
                Marshal.Copy(hashedPasswordPtr.passwords, hashedResult, 0, hashedPasswordPtr.length);
                for (int i = 0; i < hashedResult.Length; i++)
                {
                    string currentString = Marshal.PtrToStringAnsi(hashedResult[i]);
                    result.Add(currentString);
                    Argon2LinuxWrapper.free_cstring(hashedResult[i]);
                }
            }
            else
            {
                Argon2ThreadResult hashedPasswordPtr = Argon2WindowsWrapper.argon2_hash_thread(passwordsToHash, passwordsToHash.Length);
                nint[] hashedResult = new nint[hashedPasswordPtr.length];
                Marshal.Copy(hashedPasswordPtr.passwords, hashedResult, 0, hashedPasswordPtr.length);
                for (int i = 0; i < hashedResult.Length; i++)
                {
                    string currentString = Marshal.PtrToStringAnsi(hashedResult[i]);
                    result.Add(currentString);
                    Argon2WindowsWrapper.free_cstring(hashedResult[i]);
                }
            }
            string[] stringArrayResult = result.ToArray();
            DateTime end = DateTime.UtcNow;
            this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.PasswordHash, nameof(Argon2Wrapper));
            return stringArrayResult;
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

            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                IntPtr hashedPtr = Argon2LinuxWrapper.argon2_hash(passToHash);
                string hashed = Marshal.PtrToStringAnsi(hashedPtr);
                Argon2LinuxWrapper.free_cstring(hashedPtr);
                DateTime end = DateTime.UtcNow;
                this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.PasswordHash, nameof(Argon2Wrapper));
                return hashed;
            }
            else
            {
                IntPtr hashedPtr = Argon2WindowsWrapper.argon2_hash(passToHash);
                string hashed = Marshal.PtrToStringAnsi(hashedPtr);
                Argon2WindowsWrapper.free_cstring(hashedPtr);
                DateTime end = DateTime.UtcNow;
                this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.PasswordHash, nameof(Argon2Wrapper));
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

            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {

                bool result = Argon2LinuxWrapper.argon2_verify(hashedPasswrod, password);
                DateTime end = DateTime.UtcNow;
                this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.PasswordHash, nameof(Argon2Wrapper));
                return result;
            }
            else
            {
                bool result = Argon2WindowsWrapper.argon2_verify(hashedPasswrod, password);
                DateTime end = DateTime.UtcNow;
                this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.PasswordHash, nameof(Argon2Wrapper));
                return result;
            }
        }

        /// <summary>
        /// Verifies that a none hahsed password matches the hashed password using Argon2 algorithm on a new thread.
        /// </summary>
        /// <param name="hashedPasswrod"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public bool VerifyPasswordThread(string hashedPasswrod, string password)
        {
            if (string.IsNullOrEmpty(hashedPasswrod) || string.IsNullOrEmpty(password))
            {
                throw new Exception("You must provide a hashed password and password to verify with argon2");
            }

            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                bool result = Argon2LinuxWrapper.argon2_verify_thread(hashedPasswrod, password);
                DateTime end = DateTime.UtcNow;
                this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.PasswordHash, nameof(Argon2Wrapper));
                return result;
            }
            else
            {
                bool result = Argon2WindowsWrapper.argon2_verify_thread(hashedPasswrod, password);
                DateTime end = DateTime.UtcNow;
                this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.PasswordHash, nameof(Argon2Wrapper));
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
            if (string.IsNullOrEmpty(password))
            {
                throw new Exception("You must provide a password to hash using argon2");
            }

            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                IntPtr hashedPtr = Argon2LinuxWrapper.argon2_hash_threadpool(password);
                string hashed = Marshal.PtrToStringAnsi(hashedPtr);
                Argon2LinuxWrapper.free_cstring(hashedPtr);
                DateTime end = DateTime.UtcNow;
                this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.PasswordHash, nameof(Argon2Wrapper));
                return hashed;
            }
            else
            {
                IntPtr hashedPtr = Argon2WindowsWrapper.argon2_hash_threadpool(password);
                string hashed = Marshal.PtrToStringAnsi(hashedPtr);
                Argon2WindowsWrapper.free_cstring(hashedPtr);
                DateTime end = DateTime.UtcNow;
                this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.PasswordHash, nameof(Argon2Wrapper));
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
            if (string.IsNullOrEmpty(hashedPassword) || string.IsNullOrEmpty(verifyPassword))
            {
                throw new Exception("You must provide a hashed password and password to verify with argon2");
            }

            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {

                bool result = Argon2LinuxWrapper.argon2_verify_threadpool(hashedPassword, verifyPassword);
                DateTime end = DateTime.UtcNow;
                this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.PasswordHash, nameof(Argon2Wrapper));
                return result;
            }
            else
            {
                bool result = Argon2WindowsWrapper.argon2_verify_threadpool(hashedPassword, verifyPassword);
                DateTime end = DateTime.UtcNow;
                this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.PasswordHash, nameof(Argon2Wrapper));
                return result;
            }
        }
    }
}
