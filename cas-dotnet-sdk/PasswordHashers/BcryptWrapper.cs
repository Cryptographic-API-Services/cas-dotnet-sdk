using CasCoreLib;
using CasDotnetSdk.Helpers;

namespace CasDotnetSdk.PasswordHashers
{
    public unsafe class BcryptWrapper : IPasswordHasherBase
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
        public string HashPassword(string passwordToHash)
        {
            fixed (byte* passPtr = NativeString.ToCString(passwordToHash))
            {
                CasStringResult hashResult = NativeMethods.bcrypt_hash(passPtr);
                CasErrorHandler.ThrowIfError(hashResult.error_code, "BCrypt hash");
                return NativeString.ReadAndFree(hashResult.value);
            }
        }

        /// <summary>
        /// Hashes a password using the BCrypt algorithm with specified parameters.
        /// Max cost is 31.
        /// </summary>
        public string HashPasswordWithParameters(string passToHash, uint cost = 12)
        {
            fixed (byte* passPtr = NativeString.ToCString(passToHash))
            {
                CasStringResult hashResult = NativeMethods.bcrypt_hash_with_parameters(passPtr, cost);
                CasErrorHandler.ThrowIfError(hashResult.error_code, "BCrypt hash");
                return NativeString.ReadAndFree(hashResult.value);
            }
        }

        /// <summary>
        /// Verifies a hashed password against an unhashed password using the BCrypt algorithm.
        /// </summary>
        public bool Verify(string hashedPassword, string unhashed)
        {
            fixed (byte* passPtr = NativeString.ToCString(unhashed))
            fixed (byte* hashPtr = NativeString.ToCString(hashedPassword))
            {
                CasVerifyResult result = NativeMethods.bcrypt_verify(passPtr, hashPtr);
                CasErrorHandler.ThrowIfError(result.error_code, "BCrypt verify");
                return result.is_valid;
            }
        }
    }
}
