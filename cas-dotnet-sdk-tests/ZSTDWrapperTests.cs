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
    }
}
