using System;

namespace CasDotnetSdk.Sponges.Types
{
    internal struct Ascon128EncryptResultStruct
    {
        public IntPtr ciphertext { get; set; }
        public int length { get; set; }
    }
}
