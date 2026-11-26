using Xunit;

namespace CasDotnetSdkTests.Nist
{
    /// <summary>
    /// Locates the NIST vectors that <c>build/NistVectors.targets</c> downloads at build time and
    /// copies next to the test assembly, and pins how many vectors each test runs and skips.
    /// </summary>
    internal static class NistVectors
    {
        /// <summary>A CAVP file, e.g. <c>gcmDecrypt128.rsp</c> (a <c>NistCavpFile</c> item).</summary>
        public static string CavpPath(string fileName)
        {
            return Resolve(Path.Combine("NistVectors", "cavp", fileName));
        }

        /// <summary>An ACVP-Server <c>gen-val/json-files</c> directory's internalProjection.json.</summary>
        public static string AcvpPath(string directory)
        {
            return Resolve(Path.Combine("NistVectors", "acvp", directory, "internalProjection.json"));
        }

        /// <summary>
        /// Every vector in a file is either run or skipped, and both numbers are pinned: the files
        /// are pinned too, so a different count means the filtering changed (or the pin moved).
        /// </summary>
        public static void AssertCounts(string source, int expectedRun, int expectedSkipped, int run, int skipped)
        {
            Assert.True(run == expectedRun && skipped == expectedSkipped,
                $"{source}: ran {run} and skipped {skipped} vectors, but {expectedRun} run / {expectedSkipped} skipped are pinned. " +
                "The vector files are pinned, so the filtering changed or the pin moved: check which vectors are now run or dropped before updating these counts.");
        }

        private static string Resolve(string relativePath)
        {
            string path = Path.Combine(AppContext.BaseDirectory, relativePath);
            if (!File.Exists(path))
            {
                throw new FileNotFoundException(
                    $"NIST test vector file not found: {path}. NIST vectors are downloaded during the build " +
                    "(cas-dotnet-sdk-tests/build/NistVectors.targets): rebuild the test project with network access " +
                    "(and without -p:FetchNistVectors=false).");
            }
            return path;
        }
    }
}
