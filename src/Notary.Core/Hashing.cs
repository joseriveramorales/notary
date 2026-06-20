using System.Security.Cryptography;

namespace Notary.Core;

/// <summary>SHA-256 fingerprinting. The whole notary operates on these 32-byte hashes,
/// never on the raw file, so signing a 4 GB file costs the same as signing a one-liner.</summary>
public static class Hashing
{
    public static byte[] Sha256(byte[] data) => SHA256.HashData(data);

    public static byte[] Sha256OfFile(string path) => Sha256(File.ReadAllBytes(path));

    public static string ToHex(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();
}
