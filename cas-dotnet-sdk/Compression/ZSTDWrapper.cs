using CasCoreLib;
using CasDotnetSdk.Helpers;
using System;

namespace CasDotnetSdk.Compression
{
    public unsafe class ZSTDWrapper 
    {
        public ZSTDWrapper()
        {
        }

        /// <summary>
        /// Compresses a byte array with Zstandard (zstd).
        /// </summary>
        /// <param name="data">The data to compress.</param>
        /// <param name="level">The compression level, 0 to 22 (0 selects zstd's default, 3). Lower levels, such as 1–9,
        /// are faster but result in larger output, while higher levels, such as 10–22, compress better.</param>
        /// <exception cref="ArgumentOutOfRangeException">The level is outside 0 to 22.</exception>
        public byte[] Compress(byte[] data, int level)
        {
            if (data == null || data.Length == 0)
            {
                throw new Exception("Must pass an allocated data array to ZSTD Compression");
            }
            if (level < 0 || level > 22)
            {
                throw new ArgumentOutOfRangeException(nameof(level), level, "The ZSTD compression level must be between 0 and 22.");
            }

            fixed (byte* dataPtr = NativePin.Of(data))
            {
                ZstdCompressResult compressResult = NativeMethods.compress(dataPtr, (nuint)data.Length, (nuint)level);
                CasErrorHandler.ThrowIfError(compressResult.error_code, "ZSTD compress");
                return NativeByteBuffer.CopyAndFree(compressResult.data, compressResult.length);
            }
        }

        /// <summary>
        /// Decompresses a previously compressed byte array with ZSTD.
        /// No level is required to decompress. The output is capped at 64 MiB, so a small
        /// malicious frame can't exhaust memory.
        /// </summary>
        /// <exception cref="CasException"><see cref="CasErrorCode.DecompressionLimitExceeded"/> when the output would exceed 64 MiB.</exception>
        public byte[] Decompress(byte[] data)
        {
            if (data == null || data.Length == 0)
            {
                throw new Exception("Must pass in an allocated array of data to decompress");
            }

            fixed (byte* dataPtr = NativePin.Of(data))
            {
                ZstdCompressResult decompressResult = NativeMethods.decompress(dataPtr, (nuint)data.Length);
                CasErrorHandler.ThrowIfError(decompressResult.error_code, "ZSTD decompress");
                return NativeByteBuffer.CopyAndFree(decompressResult.data, decompressResult.length);
            }
        }
    }
}
