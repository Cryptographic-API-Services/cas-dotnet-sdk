using CasCoreLib;
using System;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Helpers
{
    /// <summary>
    /// Copies a byte buffer handed back by cas-core-lib into a managed array and
    /// then releases the native allocation via the FFI <c>free_bytes</c>.
    /// <para>
    /// This centralizes the "marshal the bytes out, then free the pointer"
    /// invariant that every pointer-returning native call must honor — the single
    /// most common source of leaks in the hand-written wrappers.
    /// </para>
    /// </summary>
    internal static unsafe class NativeByteBuffer
    {
        public static byte[] CopyAndFree(byte* ptr, nuint length)
        {
            if (ptr == null)
            {
                return Array.Empty<byte>();
            }

            int len = checked((int)length);
            byte[] managed = new byte[len];
            if (len > 0)
            {
                Marshal.Copy((IntPtr)ptr, managed, 0, len);
            }
            NativeMethods.free_bytes(ptr);
            return managed;
        }
    }
}
