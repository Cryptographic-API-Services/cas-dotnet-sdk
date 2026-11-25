using CasCoreLib;
using System;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Helpers
{
    /// <summary>
    /// Copies byte buffers handed back by cas-core-lib into managed arrays.
    /// <para>
    /// Every pointer the native layer returns is owned by the caller and must be released
    /// exactly once, through the native allocator, so that cas-core-lib's zeroizing allocator
    /// wipes it. Single-buffer results go through <see cref="CopyAndFree"/>. Multi-buffer
    /// results are read with <see cref="Copy"/> inside a <c>try</c> and released in a
    /// <c>finally</c> with their <c>free_&lt;struct&gt;</c> function, so a copy that throws
    /// can't leak the other buffers.
    /// </para>
    /// </summary>
    internal static unsafe class NativeByteBuffer
    {
        /// <summary>
        /// Copies <paramref name="length"/> bytes from <paramref name="ptr"/>, then frees the
        /// native buffer with <c>free_bytes</c>, even if the copy throws.
        /// </summary>
        public static byte[] CopyAndFree(byte* ptr, nuint length)
        {
            try
            {
                return Copy(ptr, length);
            }
            finally
            {
                // free_bytes ignores null.
                NativeMethods.free_bytes(ptr);
            }
        }

        /// <summary>
        /// Copies <paramref name="length"/> bytes from <paramref name="ptr"/> without freeing it.
        /// The caller frees the owning result struct.
        /// </summary>
        public static byte[] Copy(byte* ptr, nuint length)
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
            return managed;
        }
    }
}
