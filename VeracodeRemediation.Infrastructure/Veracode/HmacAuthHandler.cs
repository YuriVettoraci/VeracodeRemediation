using System.Security.Cryptography;
using System.Text;

namespace VeracodeRemediation.Infrastructure.Veracode;

/// <summary>
/// Handles HMAC authentication for Veracode API requests
/// </summary>
public class HmacAuthHandler
{
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
        var nonce = Guid.NewGuid().ToString("N");

        // Veracode HMAC: First sign the API key with timestamp to get signing key
        // Then sign the data string with the signing key (hex-encoded)
        var signingKeyHex = ComputeHmacHex(_apiKey, timestamp);
        var signingKeyBytes = Convert.FromHexString(signingKeyHex);
        
        var dataString = $"id={_apiId}&host={host}&url={path}&method={httpMethod}";
        var signature = ComputeHmacHex(signingKeyBytes, dataString);

        // Create the authorization header
        var authHeader = $"VERACODE-HMAC-SHA-256 id={_apiId},ts={timestamp},nonce={nonce},sig={signature}";
        return authHeader;
    }

    private static string ComputeHmacHex(string key, string data)
    {
        var keyBytes = Encoding.UTF8.GetBytes(key);
        var dataBytes = Encoding.UTF8.GetBytes(data);

        using var hmac = new HMACSHA256(keyBytes);
        var hashBytes = hmac.ComputeHash(dataBytes);
        return Convert.ToHexString(hashBytes).ToLowerInvariant();
    }

    private static string ComputeHmacHex(byte[] keyBytes, string data)
    {
        var dataBytes = Encoding.UTF8.GetBytes(data);

        using var hmac = new HMACSHA256(keyBytes);
        var hashBytes = hmac.ComputeHash(dataBytes);
        return Convert.ToHexString(hashBytes).ToLowerInvariant();
    }
}

