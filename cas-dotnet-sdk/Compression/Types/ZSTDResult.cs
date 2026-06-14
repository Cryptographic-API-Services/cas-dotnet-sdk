using System;

namespace CasDotnetSdk.Compression.Types
{
    internal struct ZSTDResult
    {
        public IntPtr data;
        public int length;
        public int error_code;
    }
}
