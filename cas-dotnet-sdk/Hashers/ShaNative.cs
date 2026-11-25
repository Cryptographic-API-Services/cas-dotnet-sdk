using CasCoreLib;
using CasDotnetSdk.Helpers;
using System;

namespace CasDotnetSdk.Hashers
{
    /// <summary>
    /// Shared marshalling for the SHA-2 and SHA-3 FFI functions, which all have the same shape.
    /// </summary>
    /// <remarks>
    /// The SHA FFI accepts a null pointer when the length is 0 and hashes it as the empty
    /// message, so null and empty input are pinned directly (no <see cref="NativePin"/>
    /// sentinel): <c>fixed</c> over a null or empty array yields a null pointer.
    /// </remarks>
    internal static unsafe class ShaNative
    {
        internal delegate SHAHashByteResult HashFn(byte* data, nuint length);
        internal delegate CasVerifyResult VerifyFn(byte* data, nuint dataLength, byte* hash, nuint hashLength);

        internal static byte[] Hash(byte[]? data, HashFn nativeHash)
        {
            fixed (byte* dataPtr = data)
            {
                SHAHashByteResult result = nativeHash(dataPtr, (nuint)(data?.Length ?? 0));
                CasErrorHandler.ThrowIfError(result.error_code, "SHA hash");
                return NativeByteBuffer.CopyAndFree(result.result_bytes_ptr, result.length);
            }
        }

        internal static bool Verify(byte[]? data, byte[] hash, string hashParamName, VerifyFn nativeVerify)
        {
            if (hash == null)
            {
                throw new ArgumentNullException(hashParamName);
            }

            fixed (byte* dataPtr = data)
            fixed (byte* hashPtr = hash)
            {
                // The native comparison is constant-time.
                CasVerifyResult result = nativeVerify(dataPtr, (nuint)(data?.Length ?? 0), hashPtr, (nuint)hash.Length);
                CasErrorHandler.ThrowIfError(result.error_code, "SHA verify");
                return result.is_valid;
            }
        }
    }
}
