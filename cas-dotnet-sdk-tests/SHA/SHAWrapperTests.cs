using CasDotnetSdk.Hashers;
using CasDotnetSdkTests.Nist;
using Xunit;

namespace CasDotnetSdkTests.Tests
{
    public class SHAWrapperTests
    {
        private readonly SHAWrapper _wrapper;

        public SHAWrapperTests()
        {
            this._wrapper = new SHAWrapper();
        }

        [Theory]
        [MemberData(nameof(SHA256NistVectors))]
        public void SHA256MatchesNistVectors(byte[] message, byte[] expectedDigest)
        {
            byte[] hashed = this._wrapper.Hash256(message);
            Assert.Equal(expectedDigest, hashed);
            Assert.True(this._wrapper.Verify256(message, expectedDigest));
        }

        [Theory]
        [MemberData(nameof(SHA512NistVectors))]
        public void SHA512MatchesNistVectors(byte[] message, byte[] expectedDigest)
        {
            byte[] hashed = this._wrapper.Hash512(message);
            Assert.Equal(expectedDigest, hashed);
            Assert.True(this._wrapper.Verify512(message, expectedDigest));
        }

        /// <summary>
        /// A null input must hash as the empty message. The expected digest is NIST's
        /// own Len = 0 vector, so this proves null, empty and the NIST answer agree, and
        /// that null/empty are passed to the native layer as a null pointer with length 0.
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

        public static IEnumerable<object[]> EmptyMessageNistVectors()
        {
            yield return new object[] { 256, EmptyMessageDigest("SHA3_256ShortMsg.rsp") };
            yield return new object[] { 512, EmptyMessageDigest("SHA3_512ShortMsg.rsp") };
        }

        internal static byte[] EmptyMessageDigest(string fileName)
        {
            object[] vector = LoadRspVectors(fileName).Single(v => ((byte[])v[0]).Length == 0);
            return (byte[])vector[1];
        }

        public static IEnumerable<object[]> SHA256NistVectors()
        {
            return LoadRspVectors("SHA3_256ShortMsg.rsp")
                .Concat(LoadRspVectors("SHA3_256LongMsg.rsp"));
        }

        public static IEnumerable<object[]> SHA512NistVectors()
        {
            return LoadRspVectors("SHA3_512ShortMsg.rsp")
                .Concat(LoadRspVectors("SHA3_512LongMsg.rsp"));
        }

        /// <summary>
        /// Every vector of a byte-oriented CAVP SHA file (SHAVS / SHA3VS ShortMsg and LongMsg) as
        /// (message, digest). The byte-oriented files hold only whole-byte messages.
        /// </summary>
        internal static IEnumerable<object[]> LoadRspVectors(string fileName)
        {
            foreach (RspRecord record in RspFile.Read(fileName, "Len"))
            {
                int bits = record.Int("Len");
                if (bits % 8 != 0)
                {
                    throw new InvalidOperationException($"Only byte-aligned NIST test vectors are supported. Found Len = {bits} in {fileName}.");
                }

                // A zero-length message is written as "Msg = 00".
                byte[] message = bits == 0 ? Array.Empty<byte>() : record.Bytes("Msg").Take(bits / 8).ToArray();
                yield return new object[] { message, record.Bytes("MD") };
            }
        }

        [Theory]
        [InlineData("SHA3_256ShortMsg.rsp", 137)]
        [InlineData("SHA3_256LongMsg.rsp", 100)]
        [InlineData("SHA3_512ShortMsg.rsp", 73)]
        [InlineData("SHA3_512LongMsg.rsp", 100)]
        public void NistVectorCountsArePinned(string fileName, int expectedRun)
        {
            NistVectors.AssertCounts(fileName, expectedRun, 0, LoadRspVectors(fileName).Count(), 0);
        }
    }
}
