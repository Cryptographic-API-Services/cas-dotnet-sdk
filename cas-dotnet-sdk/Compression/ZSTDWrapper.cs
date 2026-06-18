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
        /// Datas to the byte array to compress and the level of encryption.
        /// Zstandard (zstd) supports 22 compression levels, ranging from -22 to 22. Lower levels, such as 1–9,
        /// are faster but result in larger file sizes, while higher levels, such as 10–22, provide better compression ratios.
        /// </summary>
        public byte[] Compress(byte[] data, int level)
        {
            if (data == null || data.Length == 0)
            {
                throw new Exception("Must pass an allocated data array to ZSTD Compression");
            }
            if (level < -22 || level > 22)
            {
                throw new Exception("Please pass in a valid level for ZSTD Compression");
            }

            fixed (byte* dataPtr = NativePin.Of(data))
            {
                ZstdCompressResult compressResult = NativeMethods.compress(dataPtr, (nuint)data.Length, (nuint)level);
                CasErrorHandler.ThrowIfError(compressResult.error_code, "ZSTD compress");
                return NativeByteBuffer.CopyAndFree(compressResult.data, compressResult.length);
            }
        }

        /// <summary>
        /// Decompresses and previosuly compressed byte array with ZSTD.
        /// No level is required to decompress.
        /// </summary>
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
