namespace CasDotnetSdk.Helpers
{
    /// <summary>
    /// Stable numeric error codes surfaced by the native cas-core-lib FFI layer in the
    /// <c>error_code</c> field of every result struct. <see cref="Success"/> (0) always
    /// means the call succeeded.
    /// <para>
    /// These values mirror the <c>cas_error_code</c> mapping in cas-core-lib's
    /// <c>helpers.rs</c> and are part of the ABI contract — they must stay in sync with
    /// the native layer.
    /// </para>
    /// </summary>
    public enum CasErrorCode
    {
        /// <summary>
        /// The native layer returned a code this version of the SDK doesn't know. The raw
        /// value is in <see cref="CasException.RawErrorCode"/>.
        /// </summary>
        Unknown = -1,
        Success = 0,
        InvalidKey = 1,
        InvalidNonce = 2,
        InvalidSignature = 3,
        InvalidInput = 4,
        InvalidPemKey = 5,
        InvalidParameters = 6,
        EncryptionFailed = 7,
        DecryptionFailed = 8,
        SigningFailed = 9,
        KeyGenerationFailed = 10,
        PasswordHashingFailed = 11,
        CompressionFailed = 12,
        /// <summary>
        /// zstd decompression stopped because the output would exceed the size limit
        /// (64 MiB by default).
        /// </summary>
        DecompressionLimitExceeded = 13,
    }
}
