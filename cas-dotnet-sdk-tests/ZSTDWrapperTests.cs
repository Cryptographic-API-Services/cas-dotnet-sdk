using CasDotnetSdk.Helpers;
using CasDotnetSdk.Compression;
using System.Text;
using Xunit;

namespace CasDotnetSdkTests
{
    public class ZSTDWrapperTests
    {
        private readonly ZSTDWrapper zstd;

        public ZSTDWrapperTests()
        {
            zstd = new ZSTDWrapper();
        }

        [Fact]
        public void Compress()
        {
            byte[] dataToCompress = Encoding.UTF8.GetBytes("ThisIsSomeDataThatShouldn'tBeCompressedBecauseItIsSoTiny.");
            byte[] compress = zstd.Compress(dataToCompress, 3);
            Assert.True(!dataToCompress.SequenceEqual(compress));
        }

        [Fact]
        public void Decompress()
        {
            byte[] dataToCompress = Encoding.UTF8.GetBytes("ThisIsSomeDataThatShouldn'tBeCompressedBecauseItIsSoTiny.");
            byte[] compress = zstd.Compress(dataToCompress, 3);
            byte[] decompress = zstd.Decompress(compress);
            Assert.True(!dataToCompress.SequenceEqual(compress));
            Assert.True(!decompress.SequenceEqual(compress));
            Assert.True(Encoding.UTF8.GetString(decompress).Equals("ThisIsSomeDataThatShouldn'tBeCompressedBecauseItIsSoTiny."));
        }


        [Fact]
        public void DecompressRejectsOutputOver64MiB()
        {
            // 64 MiB + 1 byte of zeros compresses to a few KB: a small decompression bomb (#206).
            byte[] bomb = this.zstd.Compress(new byte[64 * 1024 * 1024 + 1], 3);
            CasException ex = Assert.Throws<CasException>(() => this.zstd.Decompress(bomb));
            Assert.Equal(CasErrorCode.DecompressionLimitExceeded, ex.ErrorCode);
        }

        [Fact]
        public void DecompressWithLimitEqualToOutputSucceeds()
        {
            byte[] data = Encoding.UTF8.GetBytes(string.Concat(Enumerable.Repeat("Decompress me exactly. ", 100)));
            byte[] compressed = this.zstd.Compress(data, 3);
            Assert.Equal(data, this.zstd.Decompress(compressed, data.Length));
        }

        [Fact]
        public void DecompressWithLimitOneByteSmallerThrows()
        {
            byte[] data = Encoding.UTF8.GetBytes(string.Concat(Enumerable.Repeat("Decompress me exactly. ", 100)));
            byte[] compressed = this.zstd.Compress(data, 3);
            CasException ex = Assert.Throws<CasException>(() => this.zstd.Decompress(compressed, data.Length - 1));
            Assert.Equal(CasErrorCode.DecompressionLimitExceeded, ex.ErrorCode);
        }

        [Fact]
        public void DecompressWithLimitAbove64MiBAllowsLargerOutput()
        {
            // 65 MiB is over the default cap of Decompress(data), but within an explicit higher limit (#206).
            const int size = 65 * 1024 * 1024;
            byte[] compressed = this.zstd.Compress(new byte[size], 3);
            Assert.Equal(CasErrorCode.DecompressionLimitExceeded, Assert.Throws<CasException>(() => this.zstd.Decompress(compressed)).ErrorCode);

            byte[] decompressed = this.zstd.Decompress(compressed, size);
            Assert.Equal(size, decompressed.Length);
            Assert.True(decompressed.All(b => b == 0));
        }

        [Theory]
        [InlineData(0)]
        [InlineData(-1)]
        [InlineData(int.MinValue)]
        public void DecompressWithLimitRejectsNonPositiveLimit(int maxOutputSize)
        {
            byte[] compressed = this.zstd.Compress(Encoding.UTF8.GetBytes("data"), 3);
            Assert.Throws<ArgumentOutOfRangeException>(() => this.zstd.Decompress(compressed, maxOutputSize));
        }

        [Fact]
        public void DecompressWithLimitRejectsInvalidData()
        {
            CasException ex = Assert.Throws<CasException>(() => this.zstd.Decompress(Encoding.UTF8.GetBytes("not zstd data"), 1024));
            Assert.Equal(CasErrorCode.CompressionFailed, ex.ErrorCode);
        }
    }
}
