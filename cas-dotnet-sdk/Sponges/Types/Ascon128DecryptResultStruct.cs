using System;

namespace CasDotnetSdk.Sponges.Types
{
    internal struct Ascon128DecryptResultStruct
    {
        public IntPtr plaintext { get; set; }
        public int length { get; set; }
    }
}
