using CasDotnetSdk.Compression.Types;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Compression.Linux
{
    internal static class ZSTDLinuxWrapper
    {
        [DllImport("libcas_core_lib.so")]
        public static extern ZSTDResult decompress(byte[] dataToDecompress, int dataToDecompressLength);

        [DllImport("libcas_core_lib.so")]
        public static extern ZSTDResult compress(byte[] dataToCompress, int dataToCompressLength, int level);
    }
}
