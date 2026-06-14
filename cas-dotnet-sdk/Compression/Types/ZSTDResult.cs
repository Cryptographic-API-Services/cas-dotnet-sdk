using System;

namespace CasDotnetSdk.Compression.Types
{
    internal struct ZSTDResult
    {
        public IntPtr data;
        public long length;
        public int error_code;
    }
}
