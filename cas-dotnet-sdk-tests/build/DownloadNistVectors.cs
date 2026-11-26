// MSBuild task (compiled by RoslynCodeTaskFactory, see NistVectors.targets) that downloads
// the NIST known-answer vectors the tests use into a shared, git-ignored cache and checks
// every file against its pin:
//
//   - CAVP archives (static zips on csrc.nist.gov): SHA-256 of the zip. The members the tests
//     read are extracted next to it, and their SHA-256 digests are recorded at extraction
//     and re-checked on every build.
//   - ACVP internalProjection.json files (usnistgov/ACVP-Server at a release tag): the git
//     blob SHA-1 GitHub reports for the file at that tag.
//
// The cache is shared by every configuration and target framework, so a cross-process mutex
// serializes the parallel per-framework builds of a plain `dotnet test`. Files are written
// to a temporary name and moved into place only once they match their pin.
//
// This file is not part of the test assembly (the .csproj removes build/** from Compile).

#nullable enable

using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;

public class DownloadNistVectors : Task
{
    private const string AcvpRawUrl = "https://raw.githubusercontent.com/usnistgov/ACVP-Server/{0}/gen-val/json-files/{1}/internalProjection.json";

    /// <summary>Cache root, e.g. obj/nist/.</summary>
    [Required]
    public string CacheDirectory { get; set; } = string.Empty;

    /// <summary>The ACVP-Server ref to fetch.</summary>
    [Required]
    public string AcvpRef { get; set; } = string.Empty;

    /// <summary>The ACVP-Server tag the BlobSha pins belong to. Any other ref is fetched unchecked.</summary>
    [Required]
    public string AcvpPinnedRef { get; set; } = string.Empty;

    /// <summary>Items: archive file name; metadata Url, Sha256 (empty: download and log the digest).</summary>
    public ITaskItem[] CavpArchives { get; set; } = Array.Empty<ITaskItem>();

    /// <summary>Items: local file name; metadata Archive, Member (path inside the zip).</summary>
    public ITaskItem[] CavpFiles { get; set; } = Array.Empty<ITaskItem>();

    /// <summary>Items: ACVP-Server gen-val/json-files directory; metadata BlobSha (empty: log it).</summary>
    public ITaskItem[] AcvpFiles { get; set; } = Array.Empty<ITaskItem>();

    /// <summary>False: never touch the network; use (and check) only what is cached.</summary>
    public bool Download { get; set; } = true;

    /// <summary>Cached files, with TargetPath metadata (NistVectors\cavp\... / NistVectors\acvp\...).</summary>
    [Output]
    public ITaskItem[] Files { get; set; } = Array.Empty<ITaskItem>();

    private HttpClient? _http;

    public override bool Execute()
    {
        string root = Path.GetFullPath(CacheDirectory);
        Directory.CreateDirectory(root);

        using var mutex = new Mutex(false, "cas-dotnet-sdk-nist-" + Hex(SHA256Bytes(Encoding.UTF8.GetBytes(root.ToLowerInvariant()))).Substring(0, 16));
        bool owned;
        try
        {
            owned = mutex.WaitOne(TimeSpan.FromMinutes(30));
        }
        catch (AbandonedMutexException)
        {
            owned = true;
        }
        if (!owned)
        {
            Log.LogError("Timed out waiting for another build to finish fetching NIST vectors into {0}.", root);
            return false;
        }

        try
        {
            var files = new List<ITaskItem>();
            FetchCavp(root, files);
            FetchAcvp(root, files);
            Files = files.ToArray();
            TouchIfSourcesChanged(root, files);
        }
        finally
        {
            mutex.ReleaseMutex();
            _http?.Dispose();
        }
        return !Log.HasLoggedErrors;
    }

    private void FetchCavp(string root, List<ITaskItem> files)
    {
        foreach (ITaskItem archive in CavpArchives)
        {
            string name = archive.ItemSpec;
            string pin = archive.GetMetadata("Sha256").Trim().ToLowerInvariant();
            ITaskItem[] members = CavpFiles.Where(f => string.Equals(f.GetMetadata("Archive"), name, StringComparison.OrdinalIgnoreCase)).ToArray();
            string dir = Path.Combine(root, "cavp", pin.Length == 0 ? "unpinned" : pin);
            string zip = Path.Combine(dir, name);
            string manifest = Path.Combine(dir, Path.GetFileNameWithoutExtension(name) + ".members.sha256");

            if (pin.Length == 0 || !MembersMatchManifest(dir, manifest, pin, members))
            {
                if (pin.Length > 0 && File.Exists(manifest))
                {
                    Log.LogMessage(MessageImportance.High, "Cached files from NIST CAVP {0} are missing or don't match the digests recorded when they were extracted; extracting them again.", name);
                }
                if (!EnsureArchive(archive, zip, pin))
                {
                    continue;
                }
                if (!Extract(zip, dir, manifest, Hex(SHA256File(zip)), members))
                {
                    continue;
                }
            }

            foreach (ITaskItem member in members)
            {
                files.Add(Output(Path.Combine(dir, member.ItemSpec), Path.Combine("NistVectors", "cavp", member.ItemSpec)));
            }
        }

        foreach (ITaskItem orphan in CavpFiles.Where(f => !CavpArchives.Any(a => string.Equals(a.ItemSpec, f.GetMetadata("Archive"), StringComparison.OrdinalIgnoreCase))))
        {
            Log.LogError("NistCavpFile {0} names archive '{1}', which is not a NistCavpArchive item.", orphan.ItemSpec, orphan.GetMetadata("Archive"));
        }
    }

    // True when the members were extracted from the archive with the pinned digest (the
    // manifest's "archive <sha256>" line) and each is cached with the digest recorded then.
    private static bool MembersMatchManifest(string dir, string manifest, string pin, ITaskItem[] members)
    {
        if (!File.Exists(manifest))
        {
            return false;
        }
        string[] lines = File.ReadAllLines(manifest);
        if (lines.Length == 0 || lines[0] != "archive " + pin)
        {
            return false;
        }
        var recorded = lines.Skip(1)
            .Select(l => l.Split(new[] { ' ' }, 2))
            .Where(p => p.Length == 2)
            .ToDictionary(p => p[1], p => p[0], StringComparer.Ordinal);
        foreach (ITaskItem member in members)
        {
            string path = Path.Combine(dir, member.ItemSpec);
            if (!recorded.TryGetValue(member.ItemSpec, out string? digest) || !File.Exists(path) || Hex(SHA256File(path)) != digest)
            {
                return false;
            }
        }
        return true;
    }

    private bool EnsureArchive(ITaskItem archive, string zip, string pin)
    {
        string name = archive.ItemSpec;
        if (pin.Length > 0 && File.Exists(zip))
        {
            if (Hex(SHA256File(zip)) == pin)
            {
                return true;
            }
            Log.LogMessage(MessageImportance.High, "Cached NIST CAVP {0} doesn't match its pinned SHA-256; downloading it again.", name);
            File.Delete(zip);
        }

        if (!Download)
        {
            Log.LogWarning("FetchNistVectors=false and NIST CAVP {0} isn't cached in {1}; the NIST tests that read it will fail.", name, Path.GetDirectoryName(zip));
            return false;
        }

        string url = archive.GetMetadata("Url");
        Log.LogMessage(MessageImportance.High, "Fetching NIST CAVP vectors {0}", url);
        string? temp = DownloadToTemp(url, zip);
        if (temp == null)
        {
            return false;
        }

        string actual = Hex(SHA256File(temp));
        if (pin.Length == 0)
        {
            Log.LogWarning("NIST CAVP {0} has no pinned SHA-256, so it wasn't checked. Its digest is logged below.", name);
            Log.LogMessage(MessageImportance.High, "  {0}: Sha256=\"{1}\"", name, actual);
        }
        else if (actual != pin)
        {
            File.Delete(temp);
            Log.LogError("NIST CAVP {0} from {1} doesn't match its pinned SHA-256: expected {2}, got {3}. NIST may have replaced the archive: check the change before updating the pin.", name, url, pin, actual);
            return false;
        }
        MoveIntoPlace(temp, zip);
        return true;
    }

    private bool Extract(string zip, string dir, string manifest, string archiveSha256, ITaskItem[] members)
    {
        var lines = new List<string> { "archive " + archiveSha256 };
        using (ZipArchive archive = ZipFile.OpenRead(zip))
        {
            foreach (ITaskItem member in members)
            {
                string entryName = member.GetMetadata("Member").Replace('\\', '/');
                ZipArchiveEntry? entry = archive.Entries.FirstOrDefault(e => e.FullName == entryName);
                if (entry == null)
                {
                    Log.LogError("NIST CAVP {0} has no member '{1}' (for {2}).", Path.GetFileName(zip), entryName, member.ItemSpec);
                    return false;
                }
                string path = Path.Combine(dir, member.ItemSpec);
                string temp = path + ".tmp-" + Guid.NewGuid().ToString("N");
                using (Stream source = entry.Open())
                using (FileStream target = File.Create(temp))
                {
                    source.CopyTo(target);
                }
                MoveIntoPlace(temp, path);
                lines.Add(Hex(SHA256File(path)) + " " + member.ItemSpec);
            }
        }
        File.WriteAllLines(manifest, lines);
        return true;
    }

    private void FetchAcvp(string root, List<ITaskItem> files)
    {
        bool pinned = AcvpRef == AcvpPinnedRef;
        string dir = Path.Combine(root, "acvp", Sanitize(AcvpRef));
        if (!pinned && AcvpFiles.Length > 0)
        {
            Log.LogWarning("Fetching ACVP vectors from usnistgov/ACVP-Server@{0}, not the pinned tag {1}, so their git blob SHAs weren't checked. They are logged below.", AcvpRef, AcvpPinnedRef);
        }

        foreach (ITaskItem item in AcvpFiles)
        {
            string name = item.ItemSpec;
            string path = Path.Combine(dir, name, "internalProjection.json");
            string pin = pinned ? item.GetMetadata("BlobSha").Trim().ToLowerInvariant() : string.Empty;

            // An unpinned file is re-downloaded on every build: the ref might move.
            if (File.Exists(path) && pin.Length > 0)
            {
                if (GitBlobSha(path) == pin)
                {
                    files.Add(Output(path, Path.Combine("NistVectors", "acvp", name, "internalProjection.json")));
                    continue;
                }
                Log.LogMessage(MessageImportance.High, "Cached ACVP {0} doesn't match its pinned git blob SHA; downloading it again.", name);
                File.Delete(path);
            }

            if (!Download)
            {
                if (File.Exists(path))
                {
                    files.Add(Output(path, Path.Combine("NistVectors", "acvp", name, "internalProjection.json")));
                }
                else
                {
                    Log.LogWarning("FetchNistVectors=false and ACVP {0} isn't cached in {1}; the NIST tests that read it will fail.", name, dir);
                }
                continue;
            }

            string url = string.Format(AcvpRawUrl, AcvpRef, name);
            Log.LogMessage(MessageImportance.High, "Fetching NIST ACVP vectors {0}", url);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            string? temp = DownloadToTemp(url, path);
            if (temp == null)
            {
                continue;
            }

            string actual = GitBlobSha(temp);
            if (pin.Length == 0)
            {
                Log.LogMessage(MessageImportance.High, "  {0}: BlobSha=\"{1}\"", name, actual);
                if (pinned)
                {
                    Log.LogWarning("ACVP {0} has no pinned BlobSha, so it wasn't checked; its blob SHA is logged above.", name);
                }
            }
            else if (actual != pin)
            {
                File.Delete(temp);
                Log.LogError("ACVP {0} at usnistgov/ACVP-Server@{1} doesn't match its pinned git blob SHA: expected {2}, got {3}.", name, AcvpRef, pin, actual);
                continue;
            }
            MoveIntoPlace(temp, path);
            files.Add(Output(path, Path.Combine("NistVectors", "acvp", name, "internalProjection.json")));
        }
    }

    // The files are copied to the output with PreserveNewest, which copies only a source newer
    // than its output copy. After switching the ACVP ref or a CAVP pin back to files cached
    // earlier, those are older than the output copies of the files served in between, so they
    // are touched whenever the set of served cache paths differs from the previous build's.
    private static void TouchIfSourcesChanged(string root, List<ITaskItem> files)
    {
        string marker = Path.Combine(root, "served-files.txt");
        string[] served = files.Select(f => f.ItemSpec).OrderBy(p => p, StringComparer.Ordinal).ToArray();
        if (File.Exists(marker) && File.ReadAllLines(marker).SequenceEqual(served, StringComparer.Ordinal))
        {
            return;
        }
        DateTime now = DateTime.UtcNow;
        foreach (string path in served)
        {
            File.SetLastWriteTimeUtc(path, now);
        }
        File.WriteAllLines(marker, served);
    }

    private string? DownloadToTemp(string url, string destination)
    {
        _http ??= CreateClient();
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        string temp = destination + ".tmp-" + Guid.NewGuid().ToString("N");
        for (int attempt = 1; ; attempt++)
        {
            try
            {
                using (HttpResponseMessage response = _http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead).GetAwaiter().GetResult())
                {
                    response.EnsureSuccessStatusCode();
                    using (Stream body = response.Content.ReadAsStreamAsync().GetAwaiter().GetResult())
                    using (FileStream file = File.Create(temp))
                    {
                        body.CopyTo(file);
                    }
                }
                return temp;
            }
            catch (Exception ex) when (ex is HttpRequestException || ex is IOException || ex is System.Threading.Tasks.TaskCanceledException)
            {
                if (File.Exists(temp))
                {
                    File.Delete(temp);
                }
                if (attempt == 3)
                {
                    Log.LogError("Couldn't download {0}: {1}. Build with network access, or -p:FetchNistVectors=false to use only cached vectors.", url, ex.Message);
                    return null;
                }
                Thread.Sleep(1000 * attempt);
            }
        }
    }

    private static HttpClient CreateClient()
    {
        var client = new HttpClient { Timeout = TimeSpan.FromMinutes(10) };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("cas-dotnet-sdk-tests-nist-fetch/1.0");
        return client;
    }

    private static void MoveIntoPlace(string temp, string destination)
    {
        if (File.Exists(destination))
        {
            File.Delete(destination);
        }
        File.Move(temp, destination);
    }

    private static TaskItem Output(string path, string targetPath)
    {
        var item = new TaskItem(path);
        item.SetMetadata("TargetPath", targetPath);
        return item;
    }

    // Git's object id for a file: SHA-1 of "blob <size>\0" followed by the content.
    private static string GitBlobSha(string path)
    {
        using var sha1 = SHA1.Create();
        using FileStream stream = File.OpenRead(path);
        byte[] header = Encoding.ASCII.GetBytes("blob " + stream.Length + "\0");
        sha1.TransformBlock(header, 0, header.Length, null, 0);
        byte[] buffer = new byte[1 << 20];
        int read;
        while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
        {
            sha1.TransformBlock(buffer, 0, read, null, 0);
        }
        sha1.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
        return Hex(sha1.Hash!);
    }

    private static byte[] SHA256File(string path)
    {
        using var sha = SHA256.Create();
        using FileStream stream = File.OpenRead(path);
        return sha.ComputeHash(stream);
    }

    private static byte[] SHA256Bytes(byte[] data)
    {
        using var sha = SHA256.Create();
        return sha.ComputeHash(data);
    }

    private static string Hex(byte[] bytes)
    {
        var sb = new StringBuilder(bytes.Length * 2);
        foreach (byte b in bytes)
        {
            sb.Append(b.ToString("x2"));
        }
        return sb.ToString();
    }

    private static string Sanitize(string value)
    {
        char[] invalid = Path.GetInvalidFileNameChars();
        return new string(value.Select(c => invalid.Contains(c) ? '_' : c).ToArray());
    }
}
