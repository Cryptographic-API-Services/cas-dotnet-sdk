using CasCoreLib;
using CasDotnetSdk.Helpers;
using System;

namespace CasDotnetSdk.Hashers
{
    public unsafe class HmacWrapper : BaseWrapper
    {
        /// <summary>
        /// A wrapper class for the HMAC hashing algorithm.
        /// </summary>
        public HmacWrapper()
        {
        }

        /// <summary>
        /// Signs a message using the HMAC algorithm.
        /// </summary>
        public byte[] HmacSignBytes(byte[] key, byte[] message)
        {
            if (key == null || key.Length == 0)
            {
                throw new Exception("You must provide a key to sign with HMAC");
            }
            if (message == null || message.Length == 0)
            {
                throw new Exception("You must provide a message to sign with HMAC");
            }

            fixed (byte* keyPtr = NativePin.Of(key))
            fixed (byte* messagePtr = NativePin.Of(message))
            {
                HmacSignByteResult signed = NativeMethods.hmac_sign_bytes(keyPtr, (nuint)key.Length, messagePtr, (nuint)message.Length);
                CasErrorHandler.ThrowIfError(signed.error_code, "HMAC sign");
                return NativeByteBuffer.CopyAndFree(signed.result_bytes_ptr, signed.length);
            }
        }

        /// <summary>
        /// Verifies a message using the HMAC algorithm.
        /// </summary>
        public bool HmacVerifyBytes(byte[] key, byte[] message, byte[] signature)
        {
            if (key == null || key.Length == 0)
            {
                throw new Exception("You must provide a key to verify with HMAC");
            }
            if (message == null || message.Length == 0)
            {
                throw new Exception("You must provide a message to verify with HMAC");
            }
            if (signature == null || signature.Length == 0)
            {
                throw new Exception("You must provide a signature to verify with HMAC");
            }

            fixed (byte* keyPtr = NativePin.Of(key))
            fixed (byte* messagePtr = NativePin.Of(message))
            fixed (byte* signaturePtr = NativePin.Of(signature))
            {
                CasVerifyResult result = NativeMethods.hmac_verify_bytes(keyPtr, (nuint)key.Length, messagePtr, (nuint)message.Length, signaturePtr, (nuint)signature.Length);
                CasErrorHandler.ThrowIfError(result.error_code, "HMAC verify");
                return result.is_valid;
            }
        }
    }
}
