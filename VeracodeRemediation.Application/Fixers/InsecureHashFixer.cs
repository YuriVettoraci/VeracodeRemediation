using System.Text.RegularExpressions;
using VeracodeRemediation.Core.Models;

namespace VeracodeRemediation.Application.Fixers;

/// <summary>
/// Fixes insecure hashing algorithms (MD5, SHA1) by replacing with SHA-256
/// </summary>
public class InsecureHashFixer : BaseFixer
{
    private static readonly Regex InsecureHashPatterns = new(
        @"(MD5|SHA1|SHA-1)\.Create\(\)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public async Task<FixResult> FixAsync(Vulnerability vulnerability)
    {
        if (vulnerability.CweId != "CWE-327" || string.IsNullOrWhiteSpace(vulnerability.FilePath))
        {
            return new FixResult
            {
                VulnerabilityId = vulnerability.Id,
                Success = false,
                ErrorMessage = "Invalid vulnerability for insecure hash fix"
            };
        }

        try
        {
            var filePath = vulnerability.FilePath;
            var content = await ReadFileAsync(filePath);
            var originalContent = content;
            var lineNumber = vulnerability.LineNumber ?? 0;

            if (lineNumber > 0 && lineNumber <= content.Split('\n').Length)
            {
                var lines = content.Split('\n');
                var targetLine = lines[lineNumber - 1];

                var match = InsecureHashPatterns.Match(targetLine);
                if (match.Success)
                {
                    var insecureAlgo = match.Groups[1].Value;
                    var fixedLine = targetLine.Replace(match.Value, "SHA256.Create()");

                    lines[lineNumber - 1] = fixedLine;
                    content = string.Join("\n", lines);

                    // Add using statement if needed
                    if (!content.Contains("using System.Security.Cryptography;"))
                    {
                        var usingIndex = content.IndexOf("using");
                        if (usingIndex >= 0)
                        {
                            var insertIndex = content.IndexOf('\n', usingIndex);
                            content = content.Insert(insertIndex + 1, "using System.Security.Cryptography;\n");
                        }
                        else
                        {
                            content = "using System.Security.Cryptography;\n" + content;
                        }
                    }

                    var patch = GeneratePatch(originalContent, content, filePath);
                    return new FixResult
                    {
                        VulnerabilityId = vulnerability.Id,
                        Success = true,
                        FixedFilePath = filePath,
                        PatchContent = patch,
                        Explanation = $"Replaced insecure hashing algorithm {insecureAlgo} with SHA-256"
                    };
                }
            }

            return new FixResult
            {
                VulnerabilityId = vulnerability.Id,
                Success = false,
                ErrorMessage = "Could not identify insecure hash pattern"
            };
        }
        catch (Exception ex)
        {
            return new FixResult
            {
                VulnerabilityId = vulnerability.Id,
                Success = false,
                ErrorMessage = $"Error fixing insecure hash: {ex.Message}"
            };
        }
    }
}

