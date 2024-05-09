using CasDotnetSdk.Hybrid.Types;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Hybrid.Linux
{
    internal static class HybridEncryptionLinuxWrapper
    {
        [DllImport("Contents/libcas_core_lib.so")]
        public static extern void hybrid_encryption(AESRSAHybridInitializer initalizer);
    }
}
