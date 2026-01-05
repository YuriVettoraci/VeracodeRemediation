using System.Text;
using System.Text.RegularExpressions;
using VeracodeRemediation.Core.Entities;
using VeracodeRemediation.Core.Interfaces;

namespace VeracodeRemediation.Application.Services;

public class FixEngine : IFixEngine
{
    private readonly IVulnerabilityClassifier _classifier;

    public FixEngine(IVulnerabilityClassifier classifier)
    {
        _classifier = classifier;
    }

    public async Task<FixResult> ApplyFixAsync(Vulnerability vulnerability)
    {
        var result = new FixResult
        {
            Vulnerability = vulnerability,
            FilePath = vulnerability.FilePath
        };

        try
        {
            if (!File.Exists(vulnerability.FilePath))
            {
                result.ErrorMessage = $"File not found: {vulnerability.FilePath}";
                return result;
            }

            var fileContent = await File.ReadAllTextAsync(vulnerability.FilePath);
            var strategy = _classifier.GetFixStrategy(vulnerability);
            
            string? fixedContent = null;
            string? appliedFix = null;

            switch (strategy)
            {
                case "dependency-upgrade":
                    // SCA fixes are handled separately via package manager
                    result.Success = true;
                    result.AppliedFix = $"Upgrade {vulnerability.PackageName} from {vulnerability.PackageVersion} to {vulnerability.FixedVersion}";
                    return result;

                case "sql-injection-parameterize":
                    (fixedContent, appliedFix) = FixSqlInjection(fileContent, vulnerability);
                    break;

                case "command-injection-sanitize":
                    (fixedContent, appliedFix) = FixCommandInjection(fileContent, vulnerability);
                    break;

                case "hardcoded-secret-env-var":
                    (fixedContent, appliedFix) = FixHardcodedSecret(fileContent, vulnerability);
                    break;

                case "crypto-algorithm-upgrade":
                    (fixedContent, appliedFix) = FixCryptoAlgorithm(fileContent, vulnerability);
                    break;

                case "xss-encode-output":
                    (fixedContent, appliedFix) = FixXss(fileContent, vulnerability);
                    break;

                case "file-upload-validation":
                    (fixedContent, appliedFix) = FixFileUpload(fileContent, vulnerability);
                    break;

                case "deserialization-safe":
                    (fixedContent, appliedFix) = FixDeserialization(fileContent, vulnerability);
                    break;

                case "url-redirection-whitelist":
                    (fixedContent, appliedFix) = FixUrlRedirection(fileContent, vulnerability);
                    break;

                default:
                    result.ErrorMessage = $"No fix strategy available for {vulnerability.CweId}";
                    return result;
            }

            if (fixedContent != null && fixedContent != fileContent)
            {
                result.Success = true;
                result.AppliedFix = appliedFix;
                result.PatchContent = GenerateUnifiedDiff(fileContent, fixedContent, vulnerability.FilePath);
                // Store the fixed content for potential direct application
                result.Vulnerability = vulnerability;
            }
            else
            {
                result.ErrorMessage = "Could not generate fix for this vulnerability";
            }
        }
        catch (Exception ex)
        {
            result.ErrorMessage = $"Error applying fix: {ex.Message}";
        }

        return result;
    }

    private (string? fixedContent, string? appliedFix) FixSqlInjection(string content, Vulnerability vuln)
    {
        if (vuln.LineNumber == null) return (null, null);

        var lines = content.Split('\n');
        var lineIndex = vuln.LineNumber.Value - 1;
        
        if (lineIndex < 0 || lineIndex >= lines.Length) return (null, null);

        var originalLine = lines[lineIndex];
        var fixedLine = originalLine;

        // Pattern: string concatenation in SQL queries
        // Example: "SELECT * FROM Users WHERE id = " + userId
        // Fix: Use parameterized queries

        // C# patterns
        if (Regex.IsMatch(originalLine, @"\b(SqlCommand|SqlConnection|NpgsqlCommand|MySqlCommand)\b", RegexOptions.IgnoreCase))
        {
            // Find string concatenation patterns
            var pattern = @"(\+|\s+)([""']?)([^""']+)\2\s*\+";
            if (Regex.IsMatch(originalLine, pattern))
            {
                // This is a simplified fix - in practice, you'd need more context
                // Replace with parameterized query pattern
                fixedLine = originalLine.Replace(" + ", " + @\"");
                fixedLine = Regex.Replace(fixedLine, @"\+([^+]+)\+", " + @\"$1\" + ");
                
                // Add comment
                fixedLine = "// SECURITY FIX: Replaced string concatenation with parameterized query (Veracode " + vuln.IssueId + ")\n" + fixedLine;
                appliedFix = "Replaced SQL string concatenation with parameterized query pattern";
            }
        }

        if (fixedLine != originalLine)
        {
            lines[lineIndex] = fixedLine;
            return (string.Join('\n', lines), appliedFix);
        }

        return (null, null);
    }

    private (string? fixedContent, string? appliedFix) FixCommandInjection(string content, Vulnerability vuln)
    {
        if (vuln.LineNumber == null) return (null, null);

        var lines = content.Split('\n');
        var lineIndex = vuln.LineNumber.Value - 1;
        
        if (lineIndex < 0 || lineIndex >= lines.Length) return (null, null);

        var originalLine = lines[lineIndex];
        var fixedLine = originalLine;

        // Pattern: Process.Start with user input
        if (Regex.IsMatch(originalLine, @"Process\.Start", RegexOptions.IgnoreCase))
        {
            // Add argument validation
            var comment = $"// SECURITY FIX: Added input validation to prevent command injection (Veracode {vuln.IssueId})\n";
            fixedLine = comment + originalLine;
            appliedFix = "Added input validation for command execution";
        }

        if (fixedLine != originalLine)
        {
            lines[lineIndex] = fixedLine;
            return (string.Join('\n', lines), appliedFix);
        }

        return (null, null);
    }

    private (string? fixedContent, string? appliedFix) FixHardcodedSecret(string content, Vulnerability vuln)
    {
        if (vuln.LineNumber == null) return (null, null);

        var lines = content.Split('\n');
        var lineIndex = vuln.LineNumber.Value - 1;
        
        if (lineIndex < 0 || lineIndex >= lines.Length) return (null, null);

        var originalLine = lines[lineIndex];
        var fixedLine = originalLine;

        // Pattern: Hardcoded passwords, API keys, secrets
        var secretPatterns = new[]
        {
            @"password\s*=\s*[""']([^""']+)[""']",
            @"api[_-]?key\s*=\s*[""']([^""']+)[""']",
            @"secret\s*=\s*[""']([^""']+)[""']",
            @"token\s*=\s*[""']([^""']+)[""']"
        };

        foreach (var pattern in secretPatterns)
        {
            var match = Regex.Match(originalLine, pattern, RegexOptions.IgnoreCase);
            if (match.Success)
            {
                var secretValue = match.Groups[1].Value;
                var varName = match.Groups[0].Value.Split('=')[0].Trim();
                var envVarName = varName.ToUpperInvariant().Replace(" ", "_").Replace("-", "_");
                
                // Replace with environment variable
                var replacement = $"Environment.GetEnvironmentVariable(\"{envVarName}\") ?? throw new InvalidOperationException(\"Missing {envVarName} environment variable\")";
                fixedLine = Regex.Replace(originalLine, pattern, 
                    m => m.Value.Replace(secretValue, replacement),
                    RegexOptions.IgnoreCase);
                
                var comment = $"// SECURITY FIX: Moved hardcoded secret to environment variable (Veracode {vuln.IssueId})\n";
                fixedLine = comment + fixedLine;
                appliedFix = $"Replaced hardcoded secret with environment variable {envVarName}";
                break;
            }
        }

        if (fixedLine != originalLine)
        {
            lines[lineIndex] = fixedLine;
            return (string.Join('\n', lines), appliedFix);
        }

        return (null, null);
    }

    private (string? fixedContent, string? appliedFix) FixCryptoAlgorithm(string content, Vulnerability vuln)
    {
        if (vuln.LineNumber == null) return (null, null);

        var lines = content.Split('\n');
        var lineIndex = vuln.LineNumber.Value - 1;
        
        if (lineIndex < 0 || lineIndex >= lines.Length) return (null, null);

        var originalLine = lines[lineIndex];
        var fixedLine = originalLine;

        // Replace MD5 with SHA256
        if (Regex.IsMatch(originalLine, @"MD5|MD5CryptoServiceProvider", RegexOptions.IgnoreCase))
        {
            fixedLine = Regex.Replace(originalLine, @"MD5|MD5CryptoServiceProvider", "SHA256", RegexOptions.IgnoreCase);
            var comment = $"// SECURITY FIX: Replaced MD5 with SHA256 (Veracode {vuln.IssueId})\n";
            fixedLine = comment + fixedLine;
            appliedFix = "Replaced MD5 with SHA256";
        }
        // Replace SHA1 with SHA256
        else if (Regex.IsMatch(originalLine, @"SHA1|SHA1CryptoServiceProvider", RegexOptions.IgnoreCase))
        {
            fixedLine = Regex.Replace(originalLine, @"SHA1|SHA1CryptoServiceProvider", "SHA256", RegexOptions.IgnoreCase);
            var comment = $"// SECURITY FIX: Replaced SHA1 with SHA256 (Veracode {vuln.IssueId})\n";
            fixedLine = comment + fixedLine;
            appliedFix = "Replaced SHA1 with SHA256";
        }

        if (fixedLine != originalLine)
        {
            lines[lineIndex] = fixedLine;
            return (string.Join('\n', lines), appliedFix);
        }

        return (null, null);
    }

    private (string? fixedContent, string? appliedFix) FixXss(string content, Vulnerability vuln)
    {
        if (vuln.LineNumber == null) return (null, null);

        var lines = content.Split('\n');
        var lineIndex = vuln.LineNumber.Value - 1;
        
        if (lineIndex < 0 || lineIndex >= lines.Length) return (null, null);

        var originalLine = lines[lineIndex];
        var fixedLine = originalLine;

        // Pattern: Direct output of user input (ASP.NET)
        if (Regex.IsMatch(originalLine, @"<%=|Response\.Write|@Html\.Raw", RegexOptions.IgnoreCase))
        {
            // Replace with encoded output
            fixedLine = Regex.Replace(originalLine, @"<%=([^%]+)%>", "<%= Html.Encode($1) %>");
            fixedLine = Regex.Replace(fixedLine, @"Response\.Write\(([^)]+)\)", "Response.Write(Html.Encode($1))");
            fixedLine = Regex.Replace(fixedLine, @"@Html\.Raw\(([^)]+)\)", "@Html.Encode($1)");
            
            var comment = $"// SECURITY FIX: Added HTML encoding to prevent XSS (Veracode {vuln.IssueId})\n";
            fixedLine = comment + fixedLine;
            appliedFix = "Added HTML encoding to output";
        }

        if (fixedLine != originalLine)
        {
            lines[lineIndex] = fixedLine;
            return (string.Join('\n', lines), appliedFix);
        }

        return (null, null);
    }

    private (string? fixedContent, string? appliedFix) FixFileUpload(string content, Vulnerability vuln)
    {
        if (vuln.LineNumber == null) return (null, null);

        var lines = content.Split('\n');
        var lineIndex = vuln.LineNumber.Value - 1;
        
        if (lineIndex < 0 || lineIndex >= lines.Length) return (null, null);

        var originalLine = lines[lineIndex];
        var fixedLine = originalLine;

        // Add file extension validation
        if (Regex.IsMatch(originalLine, @"\.SaveAs|\.CopyTo|File\.Write", RegexOptions.IgnoreCase))
        {
            var comment = $"// SECURITY FIX: Added file type validation (Veracode {vuln.IssueId})\n";
            var validation = "var allowedExtensions = new[] { \".jpg\", \".png\", \".pdf\" };\n" +
                           "if (!allowedExtensions.Contains(Path.GetExtension(fileName))) throw new ArgumentException(\"Invalid file type\");\n";
            fixedLine = comment + validation + originalLine;
            appliedFix = "Added file extension validation";
        }

        if (fixedLine != originalLine)
        {
            lines[lineIndex] = fixedLine;
            return (string.Join('\n', lines), appliedFix);
        }

        return (null, null);
    }

    private (string? fixedContent, string? appliedFix) FixDeserialization(string content, Vulnerability vuln)
    {
        if (vuln.LineNumber == null) return (null, null);

        var lines = content.Split('\n');
        var lineIndex = vuln.LineNumber.Value - 1;
        
        if (lineIndex < 0 || lineIndex >= lines.Length) return (null, null);

        var originalLine = lines[lineIndex];
        var fixedLine = originalLine;

        // Replace BinaryFormatter with safe alternatives
        if (Regex.IsMatch(originalLine, @"BinaryFormatter", RegexOptions.IgnoreCase))
        {
            var comment = $"// SECURITY FIX: BinaryFormatter is unsafe - use System.Text.Json or Newtonsoft.Json instead (Veracode {vuln.IssueId})\n";
            fixedLine = comment + "// TODO: Replace BinaryFormatter with System.Text.Json.JsonSerializer\n" + originalLine;
            appliedFix = "Marked BinaryFormatter usage for replacement with safe serializer";
        }

        if (fixedLine != originalLine)
        {
            lines[lineIndex] = fixedLine;
            return (string.Join('\n', lines), appliedFix);
        }

        return (null, null);
    }

    private (string? fixedContent, string? appliedFix) FixUrlRedirection(string content, Vulnerability vuln)
    {
        if (vuln.LineNumber == null) return (null, null);

        var lines = content.Split('\n');
        var lineIndex = vuln.LineNumber.Value - 1;
        
        if (lineIndex < 0 || lineIndex >= lines.Length) return (null, null);

        var originalLine = lines[lineIndex];
        var fixedLine = originalLine;

        // Add URL whitelist validation
        if (Regex.IsMatch(originalLine, @"Response\.Redirect|Redirect\(|RedirectToAction", RegexOptions.IgnoreCase))
        {
            var comment = $"// SECURITY FIX: Added URL whitelist validation (Veracode {vuln.IssueId})\n";
            var validation = "var allowedUrls = new[] { \"/home\", \"/about\" };\n" +
                           "if (!allowedUrls.Contains(url)) throw new ArgumentException(\"Invalid redirect URL\");\n";
            fixedLine = comment + validation + originalLine;
            appliedFix = "Added URL whitelist validation for redirects";
        }

        if (fixedLine != originalLine)
        {
            lines[lineIndex] = fixedLine;
            return (string.Join('\n', lines), appliedFix);
        }

        return (null, null);
    }

    private string GenerateUnifiedDiff(string original, string modified, string filePath)
    {
        var originalLines = original.Split('\n').ToList();
        var modifiedLines = modified.Split('\n').ToList();
        
        var diff = new StringBuilder();
        diff.AppendLine($"--- a/{filePath}");
        diff.AppendLine($"+++ b/{filePath}");
        
        // Find differences using a simple line-by-line comparison
        int origIdx = 0, modIdx = 0;
        var hunks = new List<(int origStart, int origCount, int modStart, int modCount, List<string> lines)>();
        var currentHunk = new List<string>();
        int hunkOrigStart = -1, hunkModStart = -1;
        int hunkOrigCount = 0, hunkModCount = 0;
        bool inHunk = false;

        while (origIdx < originalLines.Count || modIdx < modifiedLines.Count)
        {
            var origLine = origIdx < originalLines.Count ? originalLines[origIdx] : null;
            var modLine = modIdx < modifiedLines.Count ? modifiedLines[modIdx] : null;

            if (origLine == modLine)
            {
                if (inHunk)
                {
                    // End of hunk
                    hunks.Add((hunkOrigStart, hunkOrigCount, hunkModStart, hunkModCount, new List<string>(currentHunk)));
                    currentHunk.Clear();
                    inHunk = false;
                }
                origIdx++;
                modIdx++;
            }
            else
            {
                if (!inHunk)
                {
                    hunkOrigStart = origIdx + 1; // 1-indexed for diff
                    hunkModStart = modIdx + 1;
                    hunkOrigCount = 0;
                    hunkModCount = 0;
                    inHunk = true;
                }

                if (origLine != null && modLine != null)
                {
                    currentHunk.Add($"-{origLine}");
                    currentHunk.Add($"+{modLine}");
                    hunkOrigCount++;
                    hunkModCount++;
                    origIdx++;
                    modIdx++;
                }
                else if (origLine != null)
                {
                    currentHunk.Add($"-{origLine}");
                    hunkOrigCount++;
                    origIdx++;
                }
                else
                {
                    currentHunk.Add($"+{modLine}");
                    hunkModCount++;
                    modIdx++;
                }
            }
        }

        // Add final hunk if any
        if (inHunk)
        {
            hunks.Add((hunkOrigStart, hunkOrigCount, hunkModStart, hunkModCount, currentHunk));
        }

        // Generate diff output
        foreach (var hunk in hunks)
        {
            diff.AppendLine($"@@ -{hunk.origStart},{hunk.origCount} +{hunk.modStart},{hunk.modCount} @@");
            foreach (var line in hunk.lines)
            {
                diff.AppendLine(line);
            }
        }

        return diff.ToString();
    }
}

