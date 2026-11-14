using CasDotnetSdk.Hashers;
using System.Globalization;
using Xunit;

namespace CasDotnetSdkTests.Tests
{
    public class SHAWrapperTests
    {
        private readonly SHAWrapper _wrapper;
        private const string DataDirectory = "SHA/Data";
        private const string ProjectDataDirectory = "cas-dotnet-sdk-tests/SHA/Data";

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

        internal static IEnumerable<object[]> LoadRspVectors(string fileName)
        {
            string path = ResolveVectorPath(fileName);

            string? msgHex = null;
            int? bitLength = null;

            foreach (string rawLine in File.ReadLines(path))
            {
                string line = rawLine.Trim();
                if (string.IsNullOrWhiteSpace(line) || line.StartsWith("#", StringComparison.Ordinal))
                {
                    continue;
                }

                if (line.StartsWith("Len =", StringComparison.Ordinal))
                {
                    bitLength = int.Parse(line["Len =".Length..].Trim(), CultureInfo.InvariantCulture);
                    continue;
                }

                if (line.StartsWith("Msg =", StringComparison.Ordinal))
                {
                    msgHex = line["Msg =".Length..].Trim();
                    continue;
                }

                if (!line.StartsWith("MD =", StringComparison.Ordinal) || bitLength is null || msgHex is null)
                {
                    continue;
                }

                string digestHex = line["MD =".Length..].Trim();
                yield return new object[]
                {
                    GetMessageBytes(msgHex, bitLength.Value),
                    Convert.FromHexString(digestHex)
                };

                msgHex = null;
                bitLength = null;
            }
        }

        private static byte[] GetMessageBytes(string msgHex, int bitLength)
        {
            if (bitLength == 0)
            {
                return Array.Empty<byte>();
            }

            if (bitLength % 8 != 0)
            {
                throw new InvalidOperationException($"Only byte-aligned NIST test vectors are supported. Found Len = {bitLength}.");
            }

            byte[] fullMessage = Convert.FromHexString(msgHex);
            return fullMessage.Take(bitLength / 8).ToArray();
        }

        private static string ResolveVectorPath(string fileName)
        {
            string[] candidatePaths =
            {
                Path.Combine(AppContext.BaseDirectory, DataDirectory, fileName),
                Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", ProjectDataDirectory, fileName)),
                Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", ProjectDataDirectory, fileName))
            };

            foreach (string candidatePath in candidatePaths)
            {
                if (File.Exists(candidatePath))
                {
                    return candidatePath;
                }
            }

            throw new FileNotFoundException(
                $"Missing NIST SHA vector file: {fileName}. Checked: {string.Join(", ", candidatePaths)}");
        }
    }
}
