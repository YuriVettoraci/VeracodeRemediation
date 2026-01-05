using System.Security.Cryptography;
using System.Text;

namespace VeracodeRemediation.Infrastructure.Veracode;

public class HmacAuthenticator
{
    private readonly string _apiId;
    private readonly string _apiKey;

    public HmacAuthenticator(string apiId, string apiKey)
    {
        _apiId = apiId ?? throw new ArgumentNullException(nameof(apiId));
        _apiKey = apiKey ?? throw new ArgumentNullException(nameof(apiKey));
    }

    public string GenerateAuthorizationHeader(string method, string uri, string host, string path)
    {
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString();
        var nonce = Guid.NewGuid().ToString("N");

        // Create the data string for signing
        var data = $"id={_apiId}&host={host}&url={path}&method={method.ToUpper()}";
        var signature = ComputeHmac(data, _apiKey);

        // Create the authorization header
        var authHeader = $"VERACODE-HMAC-SHA-256 id={_apiId},ts={timestamp},nonce={nonce},sig={signature}";
        return authHeader;
    }

    private string ComputeHmac(string data, string key)
    {
        // Veracode API keys are typically base64-encoded
        byte[] keyBytes;
        try
        {
            keyBytes = Convert.FromBase64String(key);
        }
        catch
        {
            // If not base64, use as-is (UTF-8)
            keyBytes = Encoding.UTF8.GetBytes(key);
        }

        using var hmac = new HMACSHA256(keyBytes);
        var hashBytes = hmac.ComputeHash(Encoding.UTF8.GetBytes(data));
        return Convert.ToHexString(hashBytes).ToLowerInvariant();
    }
}

