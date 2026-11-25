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
    }
}
