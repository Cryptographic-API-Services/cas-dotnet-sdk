using CasDotnetSdk.Fodies;
using CasDotnetSdk.Helpers;
using CasDotnetSdk.PasswordHashers.Linux;
using CasDotnetSdk.PasswordHashers.Types;
using CasDotnetSdk.PasswordHashers.Windows;
using System;
using System.Runtime.InteropServices;

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
        /// Hashes the specified password using the Argon2 algorithm with the provided memory cost, iteration count, and
        /// parallelism parameters.
        /// </summary>
        /// <remarks>This method selects the appropriate platform-specific implementation of Argon2 based
        /// on the current operating system. The choice of memory cost, iterations, and parallelism directly affects the
        /// security and performance of the hash. Ensure that the parameters are chosen according to your application's
        /// security requirements.</remarks>
        /// <param name="memoryCost">The amount of memory, in kilobytes, to use for the hashing operation. Must be a positive integer. Higher
        /// values increase security but require more system memory.</param>
        /// <param name="iterations">The number of iterations to perform during hashing. Must be a positive integer. Increasing this value makes
        /// hashing slower and more resistant to brute-force attacks.</param>
        /// <param name="parallelism">The degree of parallelism, representing the number of threads to use for hashing. Must be a positive
        /// integer. Higher values may improve performance on multi-core systems.</param>
        /// <param name="passToHash">The password to hash. Cannot be null or empty.</param>
        /// <returns>A string containing the Argon2-hashed representation of the input password.</returns>
        /// <exception cref="Exception">Thrown if passToHash is null or empty.</exception>
        [BenchmarkSender]
        public string HashPasswordWithParameters(int memoryCost, int iterations, int parallelism, string passToHash)
        {
            if (string.IsNullOrEmpty(passToHash))
            {
                throw new Exception("You must provide a password to hash using argon2");
            }
            IntPtr hashedPtr = (this._platform == OSPlatform.Linux) ?
                Argon2LinuxWrapper.argon2_hash_password_parameters(memoryCost, iterations, parallelism, passToHash) :
                Argon2WindowsWrapper.argon2_hash_password_parameters(memoryCost, iterations, parallelism, passToHash);
            string hashed = Marshal.PtrToStringAnsi(hashedPtr);
            FreeMemoryHelper.FreeCStringMemory(hashedPtr);
            return hashed;
        }


        /// <summary>
        /// Hashes a password using the Argon2 algorithm.
        /// </summary>
        /// <param name="passToHash"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        /// 
        [BenchmarkSender]
        public string HashPassword(string passToHash)
        {
            if (string.IsNullOrEmpty(passToHash))
            {
                throw new Exception("You must provide a password to hash using argon2");
            }


            IntPtr hashedPtr = (this._platform == OSPlatform.Linux) ?
                Argon2LinuxWrapper.argon2_hash(passToHash) :
                Argon2WindowsWrapper.argon2_hash(passToHash);
            string hashed = Marshal.PtrToStringAnsi(hashedPtr);
            FreeMemoryHelper.FreeCStringMemory(hashedPtr);

            return hashed;
        }

        /// <summary>
        /// Verifies that a none hahsed password matches the hashed password using Argon2 algorithm.
        /// </summary>
        /// <param name="hashedPasswrod"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        /// 
        [BenchmarkSender]
        public bool Verify(string hashedPasswrod, string password)
        {
            if (string.IsNullOrEmpty(hashedPasswrod) || string.IsNullOrEmpty(password))
            {
                throw new Exception("You must provide a hashed password and password to verify with argon2");
            }


            bool result = (this._platform == OSPlatform.Linux) ?
                Argon2LinuxWrapper.argon2_verify(hashedPasswrod, password) :
                Argon2WindowsWrapper.argon2_verify(hashedPasswrod, password);

            return result;
        }

        /// <summary>
        /// Derives an 32-byte AES256 key based off the password passed in using Argon2.
        /// </summary>
        /// <param name="password"></param>
        /// <returns></returns>
        /// 
        [BenchmarkSender]
        public byte[] DeriveAES256Key(string password)
        {

            Argon2KDFResult kdfResult = (this._platform == OSPlatform.Linux) ?
                Argon2LinuxWrapper.argon2_derive_aes_256_key(password) :
                Argon2WindowsWrapper.argon2_derive_aes_256_key(password);
            byte[] result = new byte[kdfResult.length];
            Marshal.Copy(kdfResult.key, result, 0, kdfResult.length);
            FreeMemoryHelper.FreeBytesMemory(kdfResult.key);


            return result;
        }

        /// <summary>
        /// Derives an 16-byte AES128 key based off the password passed in using Argon2.
        /// </summary>
        /// <param name="password"></param>
        /// <returns></returns>
        /// 
        [BenchmarkSender]
        public byte[] DeriveAES128Key(string password)
        {

            Argon2KDFResult kdfResult = (this._platform == OSPlatform.Linux) ?
                Argon2LinuxWrapper.argon2_derive_aes_128_key(password) :
                Argon2WindowsWrapper.argon2_derive_aes_128_key(password);
            byte[] result = new byte[kdfResult.length];
            Marshal.Copy(kdfResult.key, result, 0, kdfResult.length);
            FreeMemoryHelper.FreeBytesMemory(kdfResult.key);


            return result;
        }
    }
}
