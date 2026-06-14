using System;

namespace CasDotnetSdk.Helpers
{
    /// <summary>
    /// Translates the <c>error_code</c> field carried by native cas-core-lib result
    /// structs into a managed <see cref="CasException"/>. Every wrapper method must call
    /// <see cref="ThrowIfError"/> with the returned code <em>before</em> marshaling any
    /// pointer out of the result, because the native layer leaves those pointers null on
    /// failure.
    /// </summary>
    internal static class CasErrorHandler
    {
        /// <summary>
        /// Throws a <see cref="CasException"/> when <paramref name="errorCode"/> is
        /// non-zero. A zero code is a no-op (the call succeeded).
        /// </summary>
        /// <param name="errorCode">The <c>error_code</c> from a native result struct.</param>
        /// <param name="operation">A short description of the attempted operation, used in the exception message.</param>
        public static void ThrowIfError(int errorCode, string operation)
        {
            if (errorCode == 0)
            {
                return;
            }

            CasErrorCode mapped = Enum.IsDefined(typeof(CasErrorCode), errorCode)
                ? (CasErrorCode)errorCode
                : CasErrorCode.Success;
            throw new CasException(mapped, errorCode, $"{operation} failed: {Describe(errorCode)}");
        }

        private static string Describe(int errorCode)
        {
            switch (errorCode)
            {
                case (int)CasErrorCode.InvalidKey:
                    return "the provided key was invalid.";
                case (int)CasErrorCode.InvalidNonce:
                    return "the provided nonce was invalid.";
                case (int)CasErrorCode.InvalidSignature:
                    return "the provided signature was invalid.";
                case (int)CasErrorCode.InvalidInput:
                    return "the provided input was invalid.";
                case (int)CasErrorCode.InvalidPemKey:
                    return "the provided PEM key was invalid.";
                case (int)CasErrorCode.InvalidParameters:
                    return "the provided parameters were invalid.";
                case (int)CasErrorCode.EncryptionFailed:
                    return "encryption failed.";
                case (int)CasErrorCode.DecryptionFailed:
                    return "decryption failed.";
                case (int)CasErrorCode.SigningFailed:
                    return "signing failed.";
                case (int)CasErrorCode.KeyGenerationFailed:
                    return "key generation failed.";
                case (int)CasErrorCode.PasswordHashingFailed:
                    return "password hashing failed.";
                case (int)CasErrorCode.CompressionFailed:
                    return "compression failed.";
                default:
                    return $"the native library returned an unknown error code ({errorCode}).";
            }
        }
    }
}
