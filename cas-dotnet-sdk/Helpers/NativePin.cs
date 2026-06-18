namespace CasDotnetSdk.Helpers
{
    /// <summary>
    /// Helper for pinning byte arrays before handing them to the native layer.
    /// </summary>
    internal static class NativePin
    {
        // A 1-byte array used solely to produce a non-null pointer when an empty
        // input is pinned. `fixed (byte* p = emptyArray)` yields a null pointer,
        // but the native FFI functions assert their input pointer is non-null
        // (even though they read zero bytes when the length is 0). Hashing an empty
        // input is legitimate (e.g. NIST's Len=0 vectors), so route it through this
        // sentinel and still pass the real length of 0.
        private static readonly byte[] _sentinel = new byte[1];

        public static byte[] Of(byte[] data) => data.Length == 0 ? _sentinel : data;
    }
}
