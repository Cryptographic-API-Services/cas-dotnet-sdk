using CasDotnetSdk.Compression.Types;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Compression.Windows
{
    internal static class ZSTDWindowsWrapper
    {
        [DllImport("\\Contents\\cas_core_lib.dll")]
        public static extern ZSTDResult decompress(byte[] dataToDecompress, int dataToDecompressLength);

        [DllImport("\\Contents\\cas_core_lib.dll")]
        public static extern ZSTDResult compress(byte[] dataToCompress, int dataToCompressLength, int level);

        [DllImport("\\Contents\\cas_core_lib.dll")]
        public static extern ZSTDResult decompress_threadpool(byte[] dataToDecompress, int dataToDecompressLength);

        [DllImport("\\Contents\\cas_core_lib.dll")]
        public static extern ZSTDResult compress_threadpool(byte[] dataToCompress, int dataToCompressLength, int level);
    }
}
