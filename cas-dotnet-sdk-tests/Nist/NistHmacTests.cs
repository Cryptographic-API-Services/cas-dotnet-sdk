using CasDotnetSdk.Hashers;
using Xunit;

namespace CasDotnetSdkTests.Nist
{
    /// <summary>
    /// NIST CAVP HMAC known-answer vectors (<c>HMAC.rsp</c>, HMACVS). Only the <c>[L=32]</c>
    /// (HMAC-SHA-256) sections run: the SDK exposes HMAC-SHA-256 only; the other hash sizes are
    /// skipped. Keys both shorter and longer than the 64-byte block (hashed first) are covered.
    /// The SDK always returns the full 32-byte tag, so a truncated <c>Tlen</c> is compared with
    /// its prefix, and only full-length tags go through <see cref="HmacWrapper.HmacVerifyBytes"/>.
    /// </summary>
    public class NistHmacTests
    {
        private readonly HmacWrapper _wrapper = new HmacWrapper();

        [Fact]
        public void HmacSha256MatchesNistVectors()
        {
            int run = 0;
            int skipped = 0;
            int verified = 0;
            var failures = new List<string>();
            foreach (RspRecord record in RspFile.Read("HMAC.rsp"))
            {
                if (record["L"] != "32")
                {
                    skipped++;
                    continue;
                }
                run++;

                byte[] key = record.Bytes("Key");
                byte[] message = record.Bytes("Msg");
                byte[] expected = record.Bytes("Mac");
                Assert.Equal(record.Int("Klen"), key.Length);
                Assert.Equal(record.Int("Tlen"), expected.Length);

                byte[] mac = this._wrapper.HmacSignBytes(key, message);
                if (mac.Length != 32 || !mac.Take(expected.Length).SequenceEqual(expected))
                {
                    failures.Add($"{record} (Klen {key.Length}, Tlen {expected.Length}) mismatched");
                }
                else if (expected.Length == 32)
                {
                    if (!this._wrapper.HmacVerifyBytes(key, message, expected))
                    {
                        failures.Add($"{record} did not verify");
                    }
                    byte[] tampered = (byte[])expected.Clone();
                    tampered[0] ^= 0x01;
                    if (this._wrapper.HmacVerifyBytes(key, message, tampered))
                    {
                        failures.Add($"{record} verified a tampered tag");
                    }
                    verified++;
                }
            }

            NistVectors.AssertCounts("HMAC.rsp", 225, 1350, run, skipped);
            Assert.Equal(75, verified);
            Assert.True(failures.Count == 0, $"{failures.Count}/{run} NIST HMAC-SHA-256 vectors failed: {string.Join(", ", failures)}");
        }
    }
}
