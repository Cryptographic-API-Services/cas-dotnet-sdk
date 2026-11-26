using CasDotnetSdk.Helpers;
using CasDotnetSdk.Sponges;
using Xunit;

namespace CasDotnetSdkTests.Nist
{
    /// <summary>
    /// NIST ACVP Ascon-AEAD128 (SP 800-232) vectors against
    /// <see cref="AsconWrapper.Ascon128Encrypt(byte[], byte[], byte[], byte[])"/> and
    /// <see cref="AsconWrapper.Ascon128Decrypt(byte[], byte[], byte[], byte[])"/>.
    /// </summary>
    /// <remarks>
    /// Run: vectors without nonce masking (the API has no second key) and with byte-aligned
    /// plaintext and AD (ACVP lengths are in bits). ACVP tags are truncated to 32-128 bits; the
    /// SDK always appends the full 128-bit tag, and SP 800-232 truncates by keeping the first
    /// bits (least significant first within a byte), so the ciphertext must match exactly and
    /// the ACVP tag must be a bit prefix of the SDK's tag. A decryption vector with a truncated
    /// tag is checked by encrypting its plaintext; one that is expected to fail can only be
    /// checked with a full 128-bit tag. Everything else is skipped.
    /// </remarks>
    public class NistAsconTests
    {
        private const int FullTagBytes = 16;
        private readonly AsconWrapper _wrapper = new AsconWrapper();

        [Fact]
        public void AsconAead128MatchesNistVectors()
        {
            int run = 0;
            int skipped = 0;
            var failures = new List<string>();
            foreach (AcvpFile.Case c in AcvpFile.Load("Ascon-AEAD128-SP800-232", "Ascon", "AEAD128"))
            {
                bool encryptDirection = c.Group.GetProperty("direction").GetString() == "encrypt";
                int tagBits = c.Int("tagLen");
                bool expectSuccess = encryptDirection || c.Bool("testPassed");
                if (c.Group.GetProperty("supportsNonceMasking").GetBoolean() ||
                    c.Int("payloadLen") % 8 != 0 || c.Int("adLen") % 8 != 0 ||
                    (!expectSuccess && tagBits != 128))
                {
                    skipped++;
                    continue;
                }
                run++;

                byte[] key = c.Hex("key");
                byte[] nonce = c.Hex("nonce");
                byte[] ad = c.Hex("ad");
                byte[] pt = c.Hex("pt");
                byte[] ct = c.Hex("ct");
                byte[] tag = c.Hex("tag");

                if (!expectSuccess)
                {
                    try
                    {
                        this._wrapper.Ascon128Decrypt(nonce, key, ct.Concat(tag).ToArray(), ad);
                        failures.Add($"tcId={c.TcId} ({c.String("reason")}) decrypted");
                    }
                    catch (CasException)
                    {
                    }
                    continue;
                }

                byte[] output = this._wrapper.Ascon128Encrypt(nonce, key, pt, ad);
                if (output.Length != pt.Length + FullTagBytes || !output.AsSpan(0, pt.Length).SequenceEqual(ct))
                {
                    failures.Add($"tcId={c.TcId} ciphertext mismatched");
                }
                else if (!IsBitPrefix(tag, tagBits, output.AsSpan(pt.Length)))
                {
                    failures.Add($"tcId={c.TcId} {tagBits}-bit tag mismatched");
                }
                else if (!this._wrapper.Ascon128Decrypt(nonce, key, output, ad).SequenceEqual(pt))
                {
                    failures.Add($"tcId={c.TcId} did not decrypt");
                }
            }

            NistVectors.AssertCounts("Ascon-AEAD128-SP800-232", 7, 233, run, skipped);
            Assert.True(failures.Count == 0, $"{failures.Count}/{run} NIST Ascon-AEAD128 vectors failed: {string.Join(", ", failures)}");
        }

        // True when the first `bits` bits of `fullTag` equal `truncated`. SP 800-232 numbers the
        // bits of each byte from the least significant one, so a tag truncated mid-byte keeps
        // the low `bits % 8` bits of its last byte (the rest are zero in the ACVP hex).
        private static bool IsBitPrefix(byte[] truncated, int bits, ReadOnlySpan<byte> fullTag)
        {
            int wholeBytes = bits / 8;
            if (truncated.Length != (bits + 7) / 8 || !fullTag.Slice(0, wholeBytes).SequenceEqual(truncated.AsSpan(0, wholeBytes)))
            {
                return false;
            }
            int remainingBits = bits % 8;
            if (remainingBits == 0)
            {
                return true;
            }
            byte mask = (byte)((1 << remainingBits) - 1);
            return (fullTag[wholeBytes] & mask) == truncated[wholeBytes];
        }
    }
}
