using CasCoreLib;
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace CasDotnetSdk.Helpers
{
    /// <summary>
    /// Marshals C strings across the cas-core-lib FFI boundary.
    /// </summary>
    internal static unsafe class NativeString
    {
        /// <summary>
        /// Reads a null-terminated C string handed back by the native layer into a
        /// managed string, then releases it with the FFI <c>free_cstring</c>.
        /// </summary>
        public static string ReadAndFree(byte* ptr)
        {
            if (ptr == null)
            {
                return string.Empty;
            }
            string value = Marshal.PtrToStringUTF8((IntPtr)ptr) ?? string.Empty;
            NativeMethods.free_cstring(ptr);
            return value;
        }

        /// <summary>
        /// Encodes a managed string as a null-terminated UTF-8 buffer suitable for
        /// pinning and passing to a native <c>*const c_char</c> parameter. The
        /// returned array is always at least one byte (the terminator), so pinning
        /// it yields a non-null pointer even for an empty string.
        /// </summary>
        public static byte[] ToCString(string value)
        {
            value ??= string.Empty;
            int count = Encoding.UTF8.GetByteCount(value);
            byte[] buffer = new byte[count + 1]; // trailing byte stays 0 = null terminator
            Encoding.UTF8.GetBytes(value, 0, value.Length, buffer, 0);
            return buffer;
        }
    }
}
