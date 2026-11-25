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
        /// malicious frame can't exhaust memory. To choose a different cap, use
        /// <see cref="Decompress(byte[], int)"/>.
        /// </summary>
        /// <param name="data">The compressed data.</param>
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

        /// <summary>
        /// Decompresses a previously compressed byte array with ZSTD, producing at most
        /// <paramref name="maxOutputSize"/> bytes. Decoding stops as soon as the output would go
        /// over the limit, so a small malicious frame can't exhaust memory. Set the limit no higher
        /// than the largest output you expect from the data's source.
        /// </summary>
        /// <param name="data">The compressed data.</param>
        /// <param name="maxOutputSize">The largest decompressed size allowed, in bytes. Must be greater
        /// than 0; it can be above the 64 MiB default of <see cref="Decompress(byte[])"/>, up to
        /// <see cref="int.MaxValue"/>. Peak native memory is about this limit plus the frame's window
        /// (at most 128 MiB).</param>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="maxOutputSize"/> is 0 or negative.</exception>
        /// <exception cref="CasException"><see cref="CasErrorCode.DecompressionLimitExceeded"/> when the output would
        /// exceed <paramref name="maxOutputSize"/>; <see cref="CasErrorCode.CompressionFailed"/> when the data isn't
        /// valid zstd.</exception>
        public byte[] Decompress(byte[] data, int maxOutputSize)
        {
            if (data == null || data.Length == 0)
            {
                throw new Exception("Must pass in an allocated array of data to decompress");
            }
            if (maxOutputSize <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(maxOutputSize), maxOutputSize, "The maximum ZSTD output size must be greater than 0.");
            }

            fixed (byte* dataPtr = NativePin.Of(data))
            {
                ZstdCompressResult decompressResult = NativeMethods.decompress_with_limit(dataPtr, (nuint)data.Length, (nuint)maxOutputSize);
                CasErrorHandler.ThrowIfError(decompressResult.error_code, "ZSTD decompress");
                return NativeByteBuffer.CopyAndFree(decompressResult.data, decompressResult.length);
            }
        }
    }
}
