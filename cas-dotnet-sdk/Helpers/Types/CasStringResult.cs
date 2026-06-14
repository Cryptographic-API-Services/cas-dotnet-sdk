using System;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Helpers.Types
{
    /// <summary>
    /// Mirrors the native <c>CasStringResult</c> struct returned by cas-core-lib FFI
    /// calls that hand back a C string (e.g. a password hash). <c>value</c> is null when
    /// <c>error_code</c> is non-zero; a non-null <c>value</c> must still be freed with
    /// <see cref="FreeMemoryHelper.FreeCStringMemory"/>.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct CasStringResult
    {
        public IntPtr value;
        public int error_code;
    }
}
