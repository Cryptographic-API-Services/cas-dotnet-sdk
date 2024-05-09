using CasDotnetSdk.Hybrid.Types;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Hybrid.Windows
{
    internal static class HybridEncryptionWindowsWrapper
    {
        [DllImport("\\Contents\\cas_core_lib.dll")]
        public static extern void hybrid_encryption(AESRSAHybridInitializerStruct initalizer);
    }
}
