using System.Runtime.InteropServices;

namespace CasDotnetSdk.Helpers.Types
{
    /// <summary>
    /// Mirrors the native <c>CasVerifyResult</c> struct returned by every cas-core-lib
    /// verify-style FFI call. <c>is_valid</c> only carries meaning when
    /// <c>error_code</c> is zero; a non-zero <c>error_code</c> means the inputs were
    /// malformed rather than that the signature simply did not match.
    /// <para>
    /// The native struct is <c>{ bool is_valid; i32 error_code }</c>. We model the
    /// boolean as a raw <see cref="byte"/> rather than a <c>[MarshalAs] bool</c> so the
    /// struct stays <em>blittable</em>. A non-blittable return struct makes .NET's
    /// marshaller disagree with the SysV x64 ABI about register-vs-sret return, which
    /// shifts the call's argument registers and feeds garbage lengths into the native
    /// layer (observed as a multi-terabyte allocation abort on Linux).
    /// </para>
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct CasVerifyResult
    {
        public byte is_valid_raw;
        public int error_code;

        public bool is_valid => this.is_valid_raw != 0;
    }
}
