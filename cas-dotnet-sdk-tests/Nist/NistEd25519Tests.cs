using CasDotnetSdk.Helpers;
using CasDotnetSdk.Signatures;
using Xunit;

namespace CasDotnetSdkTests.Nist
{
    /// <summary>
    /// NIST ACVP EdDSA (FIPS 186-5) vectors for Ed25519, pure mode (no pre-hash) with an empty
    /// context, the only form the SDK signs and verifies; Ed448, pre-hash and context vectors are
    /// skipped. <see cref="ED25519Wrapper.SignBytes"/> takes the 32-byte private key <c>d</c> and
    /// returns the public key <c>q</c> derived from it, so it covers keyGen as well as
    /// deterministic sigGen.
    /// </summary>
    public class NistEd25519Tests
    {
        private readonly ED25519Wrapper _wrapper = new ED25519Wrapper();

        [Fact]
        public void PublicKeyMatchesNistKeyGenVectors()
        {
            byte[] message = System.Text.Encoding.UTF8.GetBytes("NIST ACVP EdDSA keyGen");
            int run = 0;
            int skipped = 0;
            var failures = new List<string>();
            foreach (AcvpFile.Case c in AcvpFile.Load("EDDSA-KeyGen-1.0", "EDDSA", "keyGen"))
            {
                if (c.String("curve") != "ED-25519")
                {
                    skipped++;
                    continue;
                }
                run++;

                if (!this._wrapper.SignBytes(c.Hex("d"), message).PublicKey.SequenceEqual(c.Hex("q")))
                {
                    failures.Add($"tcId={c.TcId}");
                }
            }

            NistVectors.AssertCounts("EDDSA-KeyGen-1.0", 3, 3, run, skipped);
            Assert.True(failures.Count == 0, $"{failures.Count}/{run} NIST Ed25519 keyGen vectors mismatched: {string.Join(", ", failures)}");
        }

        [Fact]
        public void SignMatchesNistSigGenVectors()
        {
            int run = 0;
            int skipped = 0;
            var failures = new List<string>();
            foreach (AcvpFile.Case c in AcvpFile.Load("EDDSA-SigGen-1.0", "EDDSA", "sigGen"))
            {
                if (c.String("curve") != "ED-25519" || c.Bool("preHash") || c.Context.Length > 0)
                {
                    skipped++;
                    continue;
                }
                run++;

                // d and q are per group in sigGen.
                byte[] q = c.Hex("q");
                byte[] message = c.Hex("message");
                byte[] expected = c.Hex("signature");
                var result = this._wrapper.SignBytes(c.Hex("d"), message);
                if (!result.PublicKey.SequenceEqual(q))
                {
                    failures.Add($"tcId={c.TcId} public key mismatched");
                }
                else if (!result.Signature.SequenceEqual(expected))
                {
                    failures.Add($"tcId={c.TcId} signature mismatched");
                }
                else if (!this._wrapper.VerifyWithPublicKeyBytes(q, expected, message))
                {
                    failures.Add($"tcId={c.TcId} NIST signature did not verify");
                }
            }

            NistVectors.AssertCounts("EDDSA-SigGen-1.0", 42, 126, run, skipped);
            Assert.True(failures.Count == 0, $"{failures.Count}/{run} NIST Ed25519 sigGen vectors failed: {string.Join(", ", failures)}");
        }

        [Fact]
        public void VerifyMatchesNistSigVerVectors()
        {
            int run = 0;
            int skipped = 0;
            var failures = new List<string>();
            foreach (AcvpFile.Case c in AcvpFile.Load("EDDSA-SigVer-1.0", "EDDSA", "sigVer"))
            {
                if (c.String("curve") != "ED-25519" || c.Bool("preHash"))
                {
                    skipped++;
                    continue;
                }
                run++;

                bool expected = c.Bool("testPassed");
                bool actual;
                try
                {
                    actual = this._wrapper.VerifyWithPublicKeyBytes(c.Hex("q"), c.Hex("signature"), c.Hex("message"));
                }
                catch (CasException) when (!expected)
                {
                    actual = false;
                }
                if (actual != expected)
                {
                    failures.Add($"tcId={c.TcId} ({c.String("reason")}) expected {expected}, got {actual}");
                }
            }

            NistVectors.AssertCounts("EDDSA-SigVer-1.0", 5, 15, run, skipped);
            Assert.True(failures.Count == 0, $"{failures.Count}/{run} NIST Ed25519 sigVer vectors failed: {string.Join(", ", failures)}");
        }
    }
}
