using System.Text;
using VeracodeRemediation.Core.Entities;
using VeracodeRemediation.Core.Interfaces;

namespace VeracodeRemediation.Application.Services;

public class PatchGenerator : IPatchGenerator
{
    public async Task<string> GeneratePatchAsync(List<FixResult> fixResults)
    {
        var patch = new StringBuilder();
        patch.AppendLine("# Veracode Security Remediation Patch");
        patch.AppendLine($"# Generated: {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC");
        patch.AppendLine();

        foreach (var result in fixResults.Where(r => r.Success && !string.IsNullOrEmpty(r.PatchContent)))
        {
            patch.AppendLine($"# Fix for {result.Vulnerability.CweId} - {result.Vulnerability.IssueId}");
            patch.AppendLine($"# Severity: {result.Vulnerability.Severity}");
            patch.AppendLine($"# File: {result.FilePath}");
            patch.AppendLine();
            patch.AppendLine(result.PatchContent);
            patch.AppendLine();
        }

        return patch.ToString();
    }

    public async Task SavePatchFileAsync(string patchContent, string outputPath)
    {
        var directory = Path.GetDirectoryName(outputPath);
        if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
        {
            Directory.CreateDirectory(directory);
        }

        await File.WriteAllTextAsync(outputPath, patchContent);
    }
}

