using System;

namespace CasDotnetSdk.Helpers
{
    /// <summary>
    /// Thrown when a native cas-core-lib FFI call reports a failure via a non-zero
    /// <c>error_code</c>. Carries the originating <see cref="CasErrorCode"/> so callers
    /// can branch on the specific failure category.
    /// </summary>
    public class CasException : Exception
    {
        /// <summary>
        /// The mapped error category. Falls back to <see cref="CasErrorCode.Success"/>
        /// only when the raw code is unrecognized (see <see cref="RawErrorCode"/>).
        /// </summary>
        public CasErrorCode ErrorCode { get; }

        /// <summary>
        /// The raw numeric error code returned by the native layer, preserved even when
        /// it does not map to a known <see cref="CasErrorCode"/>.
        /// </summary>
        public int RawErrorCode { get; }

        public CasException(CasErrorCode errorCode, int rawErrorCode, string message) : base(message)
        {
            this.ErrorCode = errorCode;
            this.RawErrorCode = rawErrorCode;
        }
    }
}
