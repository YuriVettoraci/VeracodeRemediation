using System.Text.Json;
using System.Text.RegularExpressions;
using VeracodeRemediation.Core.Interfaces;
using VeracodeRemediation.Core.Models;

namespace VeracodeRemediation.Infrastructure.Veracode;

/// <summary>
/// Implementation of Veracode API client with HMAC authentication
/// </summary>
public class VeracodeApiClient : IVeracodeApiClient
{
    private const string BaseUrl = "https://api.veracode.com";
    private readonly HmacAuthHandler _authHandler;
    private readonly HttpClient _httpClient;

    public VeracodeApiClient(string apiId, string apiKey, HttpClient? httpClient = null)
    {
        _authHandler = new HmacAuthHandler(apiId, apiKey);
        _httpClient = httpClient ?? new HttpClient();
    }

    public async Task<List<string>> GetApplicationGuidsAsync(CancellationToken cancellationToken = default)
    {
        var url = $"{BaseUrl}/appsec/v1/applications";
        var response = await MakeRequestAsync(url, HttpMethod.Get, cancellationToken);
        
        var jsonDoc = JsonDocument.Parse(response);
        var apps = jsonDoc.RootElement.GetProperty("_embedded").GetProperty("applications");
        
        var guids = new List<string>();
        foreach (var app in apps.EnumerateArray())
        {
            if (app.TryGetProperty("guid", out var guidElement))
            {
                guids.Add(guidElement.GetString() ?? string.Empty);
            }
        }
        
        return guids;
    }

    public async Task<string?> GetApplicationGuidByNameAsync(string appName, CancellationToken cancellationToken = default)
    {
        var url = $"{BaseUrl}/appsec/v1/applications?name={Uri.EscapeDataString(appName)}";
        var response = await MakeRequestAsync(url, HttpMethod.Get, cancellationToken);
        
        var jsonDoc = JsonDocument.Parse(response);
        if (jsonDoc.RootElement.TryGetProperty("_embedded", out var embedded))
        {
            if (embedded.TryGetProperty("applications", out var apps))
            {
                foreach (var app in apps.EnumerateArray())
                {
                    if (app.TryGetProperty("name", out var nameElement) && 
                        nameElement.GetString()?.Equals(appName, StringComparison.OrdinalIgnoreCase) == true)
                    {
                        if (app.TryGetProperty("guid", out var guidElement))
                        {
                            return guidElement.GetString();
                        }
                    }
                }
            }
        }
        
        return null;
    }

    public async Task<List<Vulnerability>> GetSastFindingsAsync(string appGuid, CancellationToken cancellationToken = default)
    {
        var vulnerabilities = new List<Vulnerability>();
        
        // Get scan summaries first
        var scansUrl = $"{BaseUrl}/appsec/v2/applications/{appGuid}/findings";
        var response = await MakeRequestAsync(scansUrl, HttpMethod.Get, cancellationToken);
        
        var jsonDoc = JsonDocument.Parse(response);
        
        // Parse findings from Veracode API response
        if (jsonDoc.RootElement.TryGetProperty("_embedded", out var embedded))
        {
            if (embedded.TryGetProperty("findings", out var findings))
            {
                foreach (var finding in findings.EnumerateArray())
                {
                    var vuln = ParseFinding(finding, "SAST");
                    if (vuln != null)
                    {
                        vulnerabilities.Add(vuln);
                    }
                }
            }
        }
        
        return vulnerabilities;
    }

    public async Task<List<Vulnerability>> GetScaFindingsAsync(string appGuid, CancellationToken cancellationToken = default)
    {
        var vulnerabilities = new List<Vulnerability>();
        
        // Get SCA findings
        var url = $"{BaseUrl}/appsec/v2/applications/{appGuid}/findings?scan_type=SCA";
        var response = await MakeRequestAsync(url, HttpMethod.Get, cancellationToken);
        
        var jsonDoc = JsonDocument.Parse(response);
        
        if (jsonDoc.RootElement.TryGetProperty("_embedded", out var embedded))
        {
            if (embedded.TryGetProperty("findings", out var findings))
            {
                foreach (var finding in findings.EnumerateArray())
                {
                    var vuln = ParseFinding(finding, "SCA");
                    if (vuln != null)
                    {
                        vulnerabilities.Add(vuln);
                    }
                }
            }
        }
        
        return vulnerabilities;
    }

    private static Vulnerability? ParseFinding(JsonElement finding, string issueType)
    {
        try
        {
            var vuln = new Vulnerability
            {
                IssueType = issueType
            };

            // Extract common fields
            if (finding.TryGetProperty("finding_id", out var findingId))
                vuln.Id = findingId.GetString() ?? string.Empty;
            
            if (finding.TryGetProperty("cwe", out var cwe))
            {
                if (cwe.TryGetProperty("id", out var cweId))
                    vuln.CweId = $"CWE-{cweId.GetInt32()}";
                if (cwe.TryGetProperty("name", out var cweName))
                    vuln.CweName = cweName.GetString();
            }

            if (finding.TryGetProperty("severity", out var severity))
                vuln.Severity = severity.GetInt32().ToString();

            if (finding.TryGetProperty("description", out var description))
                vuln.Description = description.GetString() ?? string.Empty;

            if (finding.TryGetProperty("remediation_status", out var remediationStatus))
            {
                // Skip if already fixed
                if (remediationStatus.GetString() == "FIXED")
                    return null;
            }

            // For SAST findings
            if (issueType == "SAST")
            {
                if (finding.TryGetProperty("finding_details", out var details))
                {
                    if (details.TryGetProperty("file_path", out var filePath))
                        vuln.FilePath = filePath.GetString() ?? string.Empty;
                    
                    if (details.TryGetProperty("file_line_number", out var lineNumber))
                        vuln.LineNumber = lineNumber.GetInt32();
                }
            }

            // For SCA findings
            if (issueType == "SCA")
            {
                if (finding.TryGetProperty("component", out var component))
                {
                    if (component.TryGetProperty("name", out var packageName))
                        vuln.PackageName = packageName.GetString();
                    
                    if (component.TryGetProperty("version", out var version))
                        vuln.PackageVersion = version.GetString();
                }

                if (finding.TryGetProperty("vulnerable_component", out var vulnerableComponent))
                {
                    if (vulnerableComponent.TryGetProperty("fixed_version", out var fixedVersion))
                        vuln.FixedVersion = fixedVersion.GetString();
                }
            }

            // Extract remediation guidance
            if (finding.TryGetProperty("remediation_guidance", out var guidance))
            {
                if (guidance.TryGetProperty("text", out var guidanceText))
                    vuln.RemediationGuidance = guidanceText.GetString() ?? string.Empty;
            }

            return vuln;
        }
        catch
        {
            return null;
        }
    }

    private async Task<string> MakeRequestAsync(string url, HttpMethod method, CancellationToken cancellationToken)
    {
        var uri = new Uri(url);
        var host = uri.Host;
        var path = uri.PathAndQuery;

        var request = new HttpRequestMessage(method, url);
        var authHeader = _authHandler.GenerateAuthorizationHeader(method.Method, url, host, path);
        request.Headers.Add("Authorization", authHeader);

        var response = await _httpClient.SendAsync(request, cancellationToken);
        response.EnsureSuccessStatusCode();

        return await response.Content.ReadAsStringAsync(cancellationToken);
    }
}
