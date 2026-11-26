using CasDotnetSdk.Helpers;
using CasDotnetSdk.PQC;
using CasDotnetSdk.PQC.Types;
using Xunit;

namespace CasDotnetSdkTests.Nist
{
    /// <summary>
    /// NIST ACVP post-quantum vectors beyond the ML-KEM decapsulation and ML-DSA sigVer tests in
    /// <c>MLKEMWrapperTests</c> / <c>MLDSAWrapperTests</c>: SLH-DSA (FIPS 205), the ML-KEM key
    /// checks (FIPS 203 sections 7.2 and 7.3), and ML-DSA key generation (FIPS 204). Vectors for
    /// other parameter sets, or that the API can't express, are skipped (counted).
    /// </summary>
    public class NistPqcTests
    {
        // SLH-DSA-SHAKE-128f sigGen, external interface, pure, deterministic, empty context:
        // exactly how cas-lib signs. The signing key is the 64-byte FIPS 205 secret key
        // (SK.seed || SK.prf || PK.seed || PK.root), the same layout ACVP uses.
        [Fact]
        public void SlhDsaSignMatchesNistSigGenVectors()
        {
            var wrapper = new SLHDSAWrapper();
            int run = 0;
            int skipped = 0;
            var failures = new List<string>();
            foreach (AcvpFile.Case c in AcvpFile.Load("SLH-DSA-sigGen-FIPS205", "SLH-DSA", "sigGen"))
            {
                if (c.String("parameterSet") != "SLH-DSA-SHAKE-128f" || !c.Bool("deterministic") ||
                    c.String("signatureInterface") != "external" || c.String("preHash") != "pure" || c.Context.Length > 0)
                {
                    skipped++;
                    continue;
                }
                run++;

                byte[] message = c.Hex("message");
                byte[] signature = wrapper.Sign(c.Hex("sk"), message);
                if (!signature.SequenceEqual(c.Hex("signature")))
                {
                    failures.Add($"tcId={c.TcId} signature mismatched");
                }
                else if (!wrapper.Verify(c.Hex("pk"), signature, message))
                {
                    failures.Add($"tcId={c.TcId} NIST signature did not verify");
                }
            }

            NistVectors.AssertCounts("SLH-DSA-sigGen-FIPS205", 1, 623, run, skipped);
            Assert.True(failures.Count == 0, $"{failures.Count}/{run} NIST SLH-DSA sigGen vectors failed: {string.Join(", ", failures)}");
        }

        // SLH-DSA-SHAKE-128f sigVer, external interface, pure, empty context. A failing vector
        // must be rejected, by returning false or (for a malformed signature) throwing.
        [Fact]
        public void SlhDsaVerifyMatchesNistSigVerVectors()
        {
            var wrapper = new SLHDSAWrapper();
            int run = 0;
            int skipped = 0;
            var failures = new List<string>();
            foreach (AcvpFile.Case c in AcvpFile.Load("SLH-DSA-sigVer-FIPS205", "SLH-DSA", "sigVer"))
            {
                if (c.String("parameterSet") != "SLH-DSA-SHAKE-128f" || c.String("signatureInterface") != "external" ||
                    c.String("preHash") != "pure" || c.Context.Length > 0)
                {
                    skipped++;
                    continue;
                }
                run++;

                bool expected = c.Bool("testPassed");
                bool actual;
                try
                {
                    actual = wrapper.Verify(c.Hex("pk"), c.Hex("signature"), c.Hex("message"));
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

            NistVectors.AssertCounts("SLH-DSA-sigVer-FIPS205", 1, 503, run, skipped);
            Assert.True(failures.Count == 0, $"{failures.Count}/{run} NIST SLH-DSA sigVer vectors failed: {string.Join(", ", failures)}");
        }

        // ML-KEM-1024 encapsulationKeyCheck (FIPS 203 section 7.2, modulus check) and
        // decapsulationKeyCheck (section 7.3, hash check). cas-lib runs both checks, so an
        // invalid key must make Encapsulate / Decapsulate throw InvalidKey, and a valid one work.
        [Fact]
        public void MlKemKeyChecksMatchNistVectors()
        {
            var wrapper = new MLKEMWrapper();
            int run = 0;
            int skipped = 0;
            var failures = new List<string>();
            foreach (AcvpFile.Case c in AcvpFile.Load("ML-KEM-encapDecap-FIPS203", "ML-KEM", "encapDecap"))
            {
                string function = c.String("function");
                if (c.String("parameterSet") != "ML-KEM-1024" || (function != "encapsulationKeyCheck" && function != "decapsulationKeyCheck"))
                {
                    skipped++;
                    continue;
                }
                run++;

                bool expectValid = c.Bool("testPassed");
                string reason = c.String("reason");
                bool accepted;
                try
                {
                    if (function == "encapsulationKeyCheck")
                    {
                        MLKemEncapsulateResult result = wrapper.Encapsulate(c.Hex("ek"));
                        accepted = result.SharedSecret.Length == 32;
                    }
                    else
                    {
                        // Any well-formed ciphertext works: a valid key decapsulates it
                        // (implicit rejection), an invalid one is refused before that.
                        accepted = wrapper.Decapsulate(c.Hex("dk"), new byte[1568]).Length == 32;
                    }
                }
                catch (CasException ex) when (!expectValid)
                {
                    accepted = false;
                    if (ex.ErrorCode != CasErrorCode.InvalidKey)
                    {
                        failures.Add($"{function} tcId={c.TcId} ({reason}) rejected with {ex.ErrorCode}, not InvalidKey");
                    }
                }
                if (accepted != expectValid)
                {
                    failures.Add($"{function} tcId={c.TcId} ({reason}) expected {(expectValid ? "accept" : "reject")}");
                }
            }

            NistVectors.AssertCounts("ML-KEM-encapDecap-FIPS203 (key checks)", 20, 145, run, skipped);
            Assert.True(failures.Count == 0, $"{failures.Count}/{run} NIST ML-KEM key-check vectors failed: {string.Join(", ", failures)}");
        }

        // ML-DSA-65 keyGen. The SDK's signing key is the 32-byte seed and no API returns the
        // public key for a seed, so key generation is checked indirectly: a signature made from
        // NIST's seed must verify under NIST's public key (and not under another vector's key).
        [Fact]
        public void MlDsaSeedMatchesNistKeyGenVectors()
        {
            var wrapper = new MLDSAWrapper();
            byte[] message = System.Text.Encoding.UTF8.GetBytes("NIST ACVP ML-DSA-65 keyGen");
            int run = 0;
            int skipped = 0;
            var failures = new List<string>();
            byte[]? previousPk = null;
            foreach (AcvpFile.Case c in AcvpFile.Load("ML-DSA-keyGen-FIPS204", "ML-DSA", "keyGen"))
            {
                if (c.String("parameterSet") != "ML-DSA-65")
                {
                    skipped++;
                    continue;
                }
                run++;

                byte[] pk = c.Hex("pk");
                byte[] signature = wrapper.Sign(c.Hex("seed"), message);
                if (!wrapper.Verify(pk, signature, message))
                {
                    failures.Add($"tcId={c.TcId} signature from NIST seed did not verify under NIST pk");
                }
                else if (previousPk != null && wrapper.Verify(previousPk, signature, message))
                {
                    failures.Add($"tcId={c.TcId} signature verified under another vector's pk");
                }
                previousPk = pk;
            }

            NistVectors.AssertCounts("ML-DSA-keyGen-FIPS204", 25, 50, run, skipped);
            Assert.True(failures.Count == 0, $"{failures.Count}/{run} NIST ML-DSA keyGen vectors failed: {string.Join(", ", failures)}");
        }
    }
}
