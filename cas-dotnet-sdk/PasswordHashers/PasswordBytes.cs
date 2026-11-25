using System;
using System.Text;

namespace CasDotnetSdk.PasswordHashers
{
    /// <summary>
    /// Encodes passwords for the native <c>*_bytes</c> password exports, which take a pointer and a
    /// length, so a password containing <c>'\0'</c> is hashed in full instead of being cut short.
    /// </summary>
    internal static class PasswordBytes
    {
        // Throws on a lone surrogate instead of replacing it with U+FFFD, so two different strings
        // never encode to the same password bytes.
        private static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

        /// <summary>
        /// Throws if <paramref name="password"/> is null or empty, and returns its UTF-8 byte count.
        /// </summary>
        /// <exception cref="ArgumentNullException"><paramref name="password"/> is null.</exception>
        /// <exception cref="ArgumentException"><paramref name="password"/> is empty or is not valid UTF-16.</exception>
        public static int Validate(string password, string paramName)
        {
            if (password == null)
            {
                throw new ArgumentNullException(paramName);
            }
            if (password.Length == 0)
            {
                throw new ArgumentException("The password must not be empty.", paramName);
            }
            try
            {
                return StrictUtf8.GetByteCount(password);
            }
            catch (EncoderFallbackException ex)
            {
                throw new ArgumentException("The password contains an unpaired surrogate and can't be encoded as UTF-8.", paramName, ex);
            }
        }

        /// <summary>
        /// Returns the UTF-8 encoding of a password that has passed <see cref="Validate"/>. The caller
        /// clears the buffer with <c>CryptographicOperations.ZeroMemory</c> once the native call returns.
        /// </summary>
        public static byte[] Encode(string password)
        {
            return StrictUtf8.GetBytes(password);
        }
    }
}
