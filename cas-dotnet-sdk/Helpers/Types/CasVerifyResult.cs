using System.Runtime.InteropServices;

namespace CasDotnetSdk.Helpers.Types
{
    /// <summary>
    /// Mirrors the native <c>CasVerifyResult</c> struct returned by every cas-core-lib
    /// verify-style FFI call. <c>is_valid</c> only carries meaning when
    /// <c>error_code</c> is zero; a non-zero <c>error_code</c> means the inputs were
    /// malformed rather than that the signature simply did not match.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct CasVerifyResult
    {
        [MarshalAs(UnmanagedType.I1)]
        public bool is_valid;
        public int error_code;
    }
}
