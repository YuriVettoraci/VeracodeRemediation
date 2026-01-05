using System.Text.RegularExpressions;
using VeracodeRemediation.Core.Models;

namespace VeracodeRemediation.Application.Fixers;

/// <summary>
/// Fixes hardcoded secrets by replacing with environment variable references
/// </summary>
public class HardcodedSecretFixer : BaseFixer
{
    private static readonly Regex SecretPatterns = new(
        @"(?:password|pwd|secret|key|token|apikey)\s*=\s*[""']([^""']+)[""']",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public async Task<FixResult> FixAsync(Vulnerability vulnerability)
    {
        if ((vulnerability.CweId != "CWE-798" && vulnerability.CweId != "CWE-259") ||
            string.IsNullOrWhiteSpace(vulnerability.FilePath))
        {
            return new FixResult
            {
                VulnerabilityId = vulnerability.Id,
                Success = false,
                ErrorMessage = "Invalid vulnerability for hardcoded secret fix"
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

                var match = SecretPatterns.Match(targetLine);
                if (match.Success)
                {
                    var secretValue = match.Groups[1].Value;
                    var varName = ExtractVariableName(targetLine);
                    var envVarName = GenerateEnvVarName(varName);

                    // Replace hardcoded value with environment variable
                    var fixedLine = targetLine.Replace(match.Groups[0].Value, 
                        $"{varName} = Environment.GetEnvironmentVariable(\"{envVarName}\") ?? throw new InvalidOperationException(\"Missing required environment variable: {envVarName}\")");

                    lines[lineNumber - 1] = fixedLine;
                    content = string.Join("\n", lines);

                    // Add using statement if not present
                    if (!content.Contains("using System;"))
                    {
                        var usingIndex = content.IndexOf("using");
                        if (usingIndex >= 0)
                        {
                            var insertIndex = content.IndexOf('\n', usingIndex);
                            content = content.Insert(insertIndex + 1, "using System;\n");
                        }
                        else
                        {
                            content = "using System;\n" + content;
                        }
                    }

                    var patch = GeneratePatch(originalContent, content, filePath);
                    return new FixResult
                    {
                        VulnerabilityId = vulnerability.Id,
                        Success = true,
                        FixedFilePath = filePath,
                        PatchContent = patch,
                        Explanation = $"Replaced hardcoded secret with environment variable reference: {envVarName}"
                    };
                }
            }

            return new FixResult
            {
                VulnerabilityId = vulnerability.Id,
                Success = false,
                ErrorMessage = "Could not identify hardcoded secret pattern"
            };
        }
        catch (Exception ex)
        {
            return new FixResult
            {
                VulnerabilityId = vulnerability.Id,
                Success = false,
                ErrorMessage = $"Error fixing hardcoded secret: {ex.Message}"
            };
        }
    }

    private static string ExtractVariableName(string line)
    {
        var match = Regex.Match(line, @"(\w+)\s*=\s*[""']");
        return match.Success ? match.Groups[1].Value : "secret";
    }

    private static string GenerateEnvVarName(string varName)
    {
        return $"SECURE_{varName.ToUpperInvariant()}";
    }
}

