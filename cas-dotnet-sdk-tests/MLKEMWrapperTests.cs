using System.Collections.Generic;
using System.Linq;
using CasDotnetSdk.PQC;
using CasDotnetSdkTests.PQC;
using Xunit;

namespace CasDotnetSdkTests
{
    public class MLKEMWrapperTests
    {
        private readonly MLKEMWrapper _wrapper;

        public MLKEMWrapperTests()
        {
            this._wrapper = new MLKEMWrapper();
        }

        [Fact]
        public void GenerateKeyPair()
        {
            var keyPair = this._wrapper.GenerateKeyPair();
            Assert.NotNull(keyPair);
            // ML-KEM-1024: 3168-byte decapsulation (secret) key, 1568-byte encapsulation (public) key.
            Assert.Equal(3168, keyPair.SecretKey.Length);
            Assert.Equal(1568, keyPair.PublicKey.Length);
        }

        [Fact]
        public void EncapsulateAndDecapsulate()
        {
            var keyPair = this._wrapper.GenerateKeyPair();
            var encapsulated = this._wrapper.Encapsulate(keyPair.PublicKey);
            Assert.Equal(1568, encapsulated.Ciphertext.Length);
            Assert.Equal(32, encapsulated.SharedSecret.Length);

            byte[] receiverSecret = this._wrapper.Decapsulate(keyPair.SecretKey, encapsulated.Ciphertext);
            Assert.Equal(encapsulated.SharedSecret, receiverSecret);
        }

        [Fact]
        public void DecapsulateTamperedCiphertextDiffersOrThrows()
        {
            var keyPair = this._wrapper.GenerateKeyPair();
            var encapsulated = this._wrapper.Encapsulate(keyPair.PublicKey);
            byte[] tampered = (byte[])encapsulated.Ciphertext.Clone();
            tampered[0] ^= 0xFF;

            // ML-KEM uses implicit rejection: a tampered ciphertext yields a different
            // (pseudorandom) shared secret rather than an error.
            byte[] receiverSecret = this._wrapper.Decapsulate(keyPair.SecretKey, tampered);
            Assert.NotEqual(encapsulated.SharedSecret, receiverSecret);
        }

        // NIST ACVP ML-KEM-1024 (FIPS 203) encapDecap decapsulation (VAL) vectors:
        // decapsulating c with dk must always produce the expected shared secret k
        // (the expected value already accounts for implicit rejection).
        [Fact]
        public void NistDecapsulationVectors()
        {
            var root = PqcVectorData.Load("nist_mlkem_1024_decaps.json");
            int count = 0;
            var failures = new List<string>();
            foreach (var group in root.GetProperty("testGroups").EnumerateArray())
            {
                foreach (var test in group.GetProperty("tests").EnumerateArray())
                {
                    int tcId = test.GetProperty("tcId").GetInt32();
                    byte[] dk = PqcVectorData.Hex(test.GetProperty("dk").GetString()!);
                    byte[] c = PqcVectorData.Hex(test.GetProperty("c").GetString()!);
                    byte[] expected = PqcVectorData.Hex(test.GetProperty("k").GetString()!);

                    byte[] actual = this._wrapper.Decapsulate(dk, c);
                    if (!actual.SequenceEqual(expected))
                    {
                        failures.Add($"tcId={tcId}");
                    }
                    count++;
                }
            }
            Assert.True(count > 0, "No NIST ML-KEM vectors were loaded.");
            Assert.True(failures.Count == 0, $"{failures.Count}/{count} NIST ML-KEM vectors mismatched: {string.Join(", ", failures)}");
        }

        // Project Wycheproof ML-KEM-1024 semi-expanded decapsulation vectors.
        //   valid   -> decaps(dk, c) == K.
        //   invalid -> inputs are malformed. A wrong dk/ciphertext length is rejected
        //              (decaps throws); a corrupted but correctly-sized key is not validated
        //              by FIPS 203 decapsulation, so it must still return a 32-byte secret
        //              without crashing. Invalid tests carry no K to compare against.
        [Fact]
        public void WycheproofDecapsulationVectors()
        {
            const int DkLen = 3168;
            const int CtLen = 1568;
            var root = PqcVectorData.Load("wycheproof_mlkem_1024_decaps.json");
            int count = 0;
            var failures = new List<string>();
            foreach (var group in root.GetProperty("testGroups").EnumerateArray())
            {
                foreach (var test in group.GetProperty("tests").EnumerateArray())
                {
                    int tcId = test.GetProperty("tcId").GetInt32();
                    byte[] dk = PqcVectorData.Hex(test.GetProperty("dk").GetString()!);
                    byte[] c = PqcVectorData.Hex(test.GetProperty("c").GetString()!);
                    bool isValid = test.GetProperty("result").GetString() == "valid";

                    if (isValid)
                    {
                        byte[] expected = PqcVectorData.Hex(test.GetProperty("K").GetString()!);
                        byte[] actual = this._wrapper.Decapsulate(dk, c);
                        if (!actual.SequenceEqual(expected))
                        {
                            failures.Add($"tcId={tcId} (valid) wrong shared secret");
                        }
                    }
                    else if (dk.Length != DkLen || c.Length != CtLen)
                    {
                        // Malformed length must be rejected.
                        if (!ThrowsOnDecapsulate(dk, c))
                        {
                            failures.Add($"tcId={tcId} (bad length) was not rejected");
                        }
                    }
                    else
                    {
                        // Correctly-sized but corrupted key: must not crash, returns 32 bytes.
                        try
                        {
                            byte[] actual = this._wrapper.Decapsulate(dk, c);
                            if (actual.Length != 32)
                            {
                                failures.Add($"tcId={tcId} (corrupted key) returned {actual.Length} bytes");
                            }
                        }
                        catch
                        {
                            // Rejecting a corrupted key is also acceptable.
                        }
                    }
                    count++;
                }
            }
            Assert.True(count > 0, "No Wycheproof ML-KEM vectors were loaded.");
            Assert.True(failures.Count == 0, $"{failures.Count}/{count} Wycheproof ML-KEM vectors mismatched: {string.Join("; ", failures)}");
        }

        private bool ThrowsOnDecapsulate(byte[] dk, byte[] c)
        {
            try
            {
                this._wrapper.Decapsulate(dk, c);
                return false;
            }
            catch
            {
                return true;
            }
        }
    }
}
