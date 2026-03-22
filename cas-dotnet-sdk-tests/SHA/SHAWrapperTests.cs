using CasDotnetSdk.Hashers;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using Xunit;

namespace CasDotnetSdkTests.Tests
{
    public class SHAWrapperTests
    {
        private readonly SHAWrapper _wrapper;
        private readonly string _testString;
        private const string DataDirectory = "SHA/Data";

        public SHAWrapperTests()
        {
            this._wrapper = new SHAWrapper();
        }

        [Fact]
        public void SHA512HashBytes()
        {
            byte[] data = Encoding.UTF8.GetBytes(this._testString);
            byte[] hashed = this._wrapper.Hash512(data);
            Assert.NotNull(hashed);
            Assert.NotEmpty(hashed);
            Assert.True(hashed.Length > 0);
        }

        [Fact]
        public void SHA512VerifyPass()
        {
            byte[] data = Encoding.UTF8.GetBytes(this._testString);
            byte[] hashed = this._wrapper.Hash512(data);
            bool isSame = this._wrapper.Verify512(data, hashed);
            Assert.True(isSame);
        }

        [Fact]
        public void SHA512VerifyFail()
        {
            byte[] data = Encoding.UTF8.GetBytes(this._testString);
            byte[] hashed = this._wrapper.Hash512(data);
            data = Encoding.UTF8.GetBytes("Not the same byte array");
            bool isSame = this._wrapper.Verify512(data, hashed);
            Assert.False(isSame);
        }

        [Fact]
        public void SHA256HashBytes()
        {
            byte[] data = Encoding.UTF8.GetBytes(this._testString);
            byte[] hashed = this._wrapper.Hash256(data);
            Assert.NotNull(hashed);
            Assert.NotEmpty(hashed);
            Assert.True(hashed.Length > 0);
        }

        [Fact]
        public void SHA256VerifyPass()
        {
            byte[] data = Encoding.UTF8.GetBytes(this._testString);
            byte[] hashed = this._wrapper.Hash256(data);
            bool isSame = this._wrapper.Verify256(data, hashed);
            Assert.True(isSame);
        }

        [Fact]
        public void SHA256VerifyFail()
        {
            byte[] data = Encoding.UTF8.GetBytes(this._testString);
            byte[] hashed = this._wrapper.Hash256(data);
            data = Encoding.UTF8.GetBytes("Not the same byte array");
            bool isSame = this._wrapper.Verify256(data, hashed);
            Assert.False(isSame);
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

        private static IEnumerable<object[]> LoadRspVectors(string fileName)
        {
            string path = Path.Combine(AppContext.BaseDirectory, DataDirectory, fileName);
            if (!File.Exists(path))
            {
                throw new FileNotFoundException($"Missing NIST SHA vector file: {path}");
            }

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
    }
}
