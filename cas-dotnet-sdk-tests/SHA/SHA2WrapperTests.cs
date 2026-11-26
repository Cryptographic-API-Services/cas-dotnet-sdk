using CasDotnetSdk.Hashers;
using CasDotnetSdkTests.Nist;
using System.Text;
using Xunit;

namespace CasDotnetSdkTests.Tests
{
    /// <summary>
    /// SHA-2 (FIPS 180-4) against the NIST CAVS byte-oriented SHA-256 / SHA-512 vectors
    /// (shabytetestvectors.zip: ShortMsg and LongMsg).
    /// </summary>
    public class SHA2WrapperTests
    {
        private readonly SHA2Wrapper _wrapper = new SHA2Wrapper();

        [Theory]
        [MemberData(nameof(SHA256NistVectors))]
        public void SHA256MatchesNistVectors(byte[] message, byte[] expectedDigest)
        {
            Assert.Equal(expectedDigest, this._wrapper.Hash256(message));
            Assert.True(this._wrapper.Verify256(message, expectedDigest));
        }

        [Theory]
        [MemberData(nameof(SHA512NistVectors))]
        public void SHA512MatchesNistVectors(byte[] message, byte[] expectedDigest)
        {
            Assert.Equal(expectedDigest, this._wrapper.Hash512(message));
            Assert.True(this._wrapper.Verify512(message, expectedDigest));
        }

        /// <summary>
        /// A null input must hash as the empty message: the expected digest is NIST's own
        /// Len = 0 vector, so null, empty and the NIST answer must all agree.
        /// </summary>
        [Theory]
        [MemberData(nameof(EmptyMessageNistVectors))]
        public void NullAndEmptyInputMatchNistEmptyMessageVector(int bits, byte[] expectedDigest)
        {
            Func<byte[]?, byte[]> hash = bits == 256 ? this._wrapper.Hash256 : this._wrapper.Hash512;
            Func<byte[]?, byte[], bool> verify = bits == 256 ? this._wrapper.Verify256 : this._wrapper.Verify512;

            Assert.Equal(expectedDigest, hash(null));
            Assert.Equal(expectedDigest, hash(Array.Empty<byte>()));
            Assert.True(verify(null, expectedDigest));
            Assert.True(verify(Array.Empty<byte>(), expectedDigest));

            byte[] tampered = (byte[])expectedDigest.Clone();
            tampered[0] ^= 0x01;
            Assert.False(verify(null, tampered));
            Assert.False(verify(null, Array.Empty<byte>()));
        }

        [Fact]
        public void VerifyRejectsNullHash()
        {
            Assert.Throws<ArgumentNullException>(() => this._wrapper.Verify256(null, null!));
            Assert.Throws<ArgumentNullException>(() => this._wrapper.Verify512(null, null!));
        }

        [Fact]
        public void FactoryReturnsSha2NotSha3()
        {
            IHasherBase hasher = HasherFactory.Get(IHasherType.SHA2);
            Assert.IsType<SHA2Wrapper>(hasher);

            // SHA-2 and SHA-3 must give different digests for the same input.
            byte[] data = Encoding.UTF8.GetBytes("abc");
            Assert.NotEqual(new SHAWrapper().Hash256(data), hasher.Hash256(data));
            Assert.NotEqual(new SHAWrapper().Hash512(data), hasher.Hash512(data));
        }

        [Theory]
        [InlineData("SHA256ShortMsg.rsp", 65)]
        [InlineData("SHA256LongMsg.rsp", 64)]
        [InlineData("SHA512ShortMsg.rsp", 129)]
        [InlineData("SHA512LongMsg.rsp", 128)]
        public void NistVectorCountsArePinned(string fileName, int expectedRun)
        {
            NistVectors.AssertCounts(fileName, expectedRun, 0, SHAWrapperTests.LoadRspVectors(fileName).Count(), 0);
        }

        public static IEnumerable<object[]> SHA256NistVectors()
        {
            return SHAWrapperTests.LoadRspVectors("SHA256ShortMsg.rsp")
                .Concat(SHAWrapperTests.LoadRspVectors("SHA256LongMsg.rsp"));
        }

        public static IEnumerable<object[]> SHA512NistVectors()
        {
            return SHAWrapperTests.LoadRspVectors("SHA512ShortMsg.rsp")
                .Concat(SHAWrapperTests.LoadRspVectors("SHA512LongMsg.rsp"));
        }

        public static IEnumerable<object[]> EmptyMessageNistVectors()
        {
            yield return new object[] { 256, SHAWrapperTests.EmptyMessageDigest("SHA256ShortMsg.rsp") };
            yield return new object[] { 512, SHAWrapperTests.EmptyMessageDigest("SHA512ShortMsg.rsp") };
        }
    }
}
