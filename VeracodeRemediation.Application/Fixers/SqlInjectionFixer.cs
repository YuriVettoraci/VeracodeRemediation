using System.Text.RegularExpressions;
using VeracodeRemediation.Core.Models;

namespace VeracodeRemediation.Application.Fixers;

/// <summary>
/// Fixes SQL Injection vulnerabilities by converting to parameterized queries
/// </summary>
public class SqlInjectionFixer : BaseFixer
{
    public async Task<FixResult> FixAsync(Vulnerability vulnerability)
    {
        if (vulnerability.CweId != "CWE-89" || string.IsNullOrWhiteSpace(vulnerability.FilePath))
        {
            return new FixResult
            {
                VulnerabilityId = vulnerability.Id,
                Success = false,
                ErrorMessage = "Invalid vulnerability for SQL injection fix"
            };
        }

        try
        {
            var filePath = vulnerability.FilePath;
            var content = await ReadFileAsync(filePath);
            var originalContent = content;
            var lineNumber = vulnerability.LineNumber ?? 0;
            string? paramName = null;

            // Find SQL query construction patterns
            var sqlPattern = new Regex(@"\b(SqlCommand|OleDbCommand|OdbcCommand)\s*\([^)]*\+[^)]*\)", RegexOptions.IgnoreCase);
            var stringConcatPattern = new Regex(@"(""[^""]*""\s*\+\s*[^;]+)", RegexOptions.Multiline);

            if (lineNumber > 0 && lineNumber <= content.Split('\n').Length)
            {
                var lines = content.Split('\n');
                var targetLine = lines[lineNumber - 1];

                // Check if line contains SQL string concatenation
                if (targetLine.Contains("SELECT", StringComparison.OrdinalIgnoreCase) ||
                    targetLine.Contains("INSERT", StringComparison.OrdinalIgnoreCase) ||
                    targetLine.Contains("UPDATE", StringComparison.OrdinalIgnoreCase) ||
                    targetLine.Contains("DELETE", StringComparison.OrdinalIgnoreCase))
                {
                    // Extract variable name from SQL command
                    var cmdMatch = Regex.Match(targetLine, @"(?:SqlCommand|OleDbCommand|OdbcCommand)\s*\(\s*(\w+)", RegexOptions.IgnoreCase);
                    if (cmdMatch.Success)
                    {
                        var cmdVar = cmdMatch.Groups[1].Value;
                        
                        // Find the SQL string construction
                        var sqlMatch = Regex.Match(targetLine, @"(""[^""]*""\s*\+\s*[^;]+)", RegexOptions.IgnoreCase);
                        if (sqlMatch.Success)
                        {
                            // Replace with parameterized query
                            var originalSql = sqlMatch.Groups[1].Value;
                            paramName = "@param1";
                            var fixedSql = originalSql.Replace("+", "").Replace("\"", "").Trim();
                            
                            // Simple parameterization - extract user input variable
                            var inputVarMatch = Regex.Match(originalSql, @"\+.*?(\w+)", RegexOptions.IgnoreCase);
                            if (inputVarMatch.Success)
                            {
                                var inputVar = inputVarMatch.Groups[1].Value;
                                fixedSql = fixedSql.Replace($"+ {inputVar}", "").Trim();
                                
                                // Add parameter
                                var newLine = targetLine.Replace(originalSql, $"\"{fixedSql}\"");
                                newLine += $"\n{cmdVar}.Parameters.AddWithValue(\"{paramName}\", {inputVar});";
                                
                                lines[lineNumber - 1] = newLine;
                                content = string.Join("\n", lines);
                            }
                        }
                    }
                }
            }

            if (content != originalContent && paramName != null)
            {
                var patch = GeneratePatch(originalContent, content, filePath);
                return new FixResult
                {
                    VulnerabilityId = vulnerability.Id,
                    Success = true,
                    FixedFilePath = filePath,
                    PatchContent = patch,
                    Explanation = $"Converted SQL string concatenation to parameterized query using {paramName} parameter"
                };
            }

            return new FixResult
            {
                VulnerabilityId = vulnerability.Id,
                Success = false,
                ErrorMessage = "Could not identify SQL injection pattern to fix"
            };
        }
        catch (Exception ex)
        {
            return new FixResult
            {
                VulnerabilityId = vulnerability.Id,
                Success = false,
                ErrorMessage = $"Error fixing SQL injection: {ex.Message}"
            };
        }
    }
}

