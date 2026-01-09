using System.Security.Cryptography;
using System.Text;

namespace VeracodeRemediation.Infrastructure.Veracode;

/// <summary>
/// Handles HMAC authentication for Veracode API requests
/// Following the official Veracode HMAC signing algorithm
/// </summary>
public class HmacAuthHandler
{
    private const string VeracodeRequestVersionString = "vcode_request_version_1";
    private readonly string _apiId;
    private readonly string _apiKey;

    public HmacAuthHandler(string apiId, string apiKey)
    {
        _apiId = apiId ?? throw new ArgumentNullException(nameof(apiId));
        _apiKey = apiKey ?? throw new ArgumentNullException(nameof(apiKey));
    }

    public string GenerateAuthorizationHeader(string httpMethod, string url, string host, string path)
    {
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString();
        var nonce = GenerateNonce();

        // Build data string as per Veracode specification
        var dataString = $"id={_apiId}&host={host}&url={path}&method={httpMethod}";
        
        // Generate signature using Veracode's chained HMAC process
        var signature = GetSignature(_apiKey, dataString, timestamp, nonce);

        // Create the authorization header
        var authHeader = $"VERACODE-HMAC-SHA-256 id={_apiId},ts={timestamp},nonce={nonce},sig={signature}";
        return authHeader;
    }

    /// <summary>
    /// Generate signature following Veracode's chained HMAC algorithm:
    /// 1. HMAC(nonce, key) -> encryptedNonce
    /// 2. HMAC(timestamp, encryptedNonce) -> encryptedTimestamp
    /// 3. HMAC("vcode_request_version_1", encryptedTimestamp) -> signingKey
    /// 4. HMAC(data, signingKey) -> signature
    /// </summary>
    private static string GetSignature(string key, string data, string timestamp, string nonce)
    {
        // Convert hex string key to bytes
        var keyBytes = Convert.FromHexString(key);
        var nonceBytes = Convert.FromHexString(nonce);

        // Step 1: HMAC(nonce, key)
        var encryptedNonce = HmacSha256(nonceBytes, keyBytes);

        // Step 2: HMAC(timestamp, encryptedNonce)
        var encryptedTimestamp = HmacSha256(timestamp, encryptedNonce);

        // Step 3: HMAC("vcode_request_version_1", encryptedTimestamp)
        var signingKey = HmacSha256(VeracodeRequestVersionString, encryptedTimestamp);

        // Step 4: HMAC(data, signingKey)
        var signature = HmacSha256(data, signingKey);

        return Convert.ToHexString(signature).ToLowerInvariant();
    }

    private static byte[] HmacSha256(string data, byte[] key)
    {
        using var hmac = new HMACSHA256(key);
        return hmac.ComputeHash(Encoding.UTF8.GetBytes(data));
    }

    private static byte[] HmacSha256(byte[] data, byte[] key)
    {
        using var hmac = new HMACSHA256(key);
        return hmac.ComputeHash(data);
    }

    private static string GenerateNonce()
    {
        var bytes = new byte[16];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(bytes);
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}

