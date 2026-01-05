using System.Text;
using VeracodeRemediation.Core.Interfaces;
using VeracodeRemediation.Core.Models;

namespace VeracodeRemediation.Application.Generators;

/// <summary>
/// Generates unified diff patch files from fix results
/// </summary>
public class PatchGenerator : IPatchGenerator
{
    public async Task<string> GeneratePatchFileAsync(List<FixResult> fixResults, string outputPath, CancellationToken cancellationToken = default)
    {
        var patchContent = new StringBuilder();
        patchContent.AppendLine("# Veracode Security Remediation Patch");
        patchContent.AppendLine($"# Generated: {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC");
        patchContent.AppendLine($"# Total fixes: {fixResults.Count(f => f.Success)}");
        patchContent.AppendLine();

        foreach (var result in fixResults.Where(f => f.Success && !string.IsNullOrWhiteSpace(f.PatchContent)))
        {
            patchContent.AppendLine($"# Fix for vulnerability: {result.VulnerabilityId}");
            if (!string.IsNullOrWhiteSpace(result.Explanation))
            {
                patchContent.AppendLine($"# {result.Explanation}");
            }
            patchContent.AppendLine();
            patchContent.AppendLine(result.PatchContent);
            patchContent.AppendLine();
        }

        var fullPath = Path.IsPathRooted(outputPath) 
            ? outputPath 
            : Path.Combine(Directory.GetCurrentDirectory(), outputPath);

        var directory = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
        {
            Directory.CreateDirectory(directory);
        }

        await File.WriteAllTextAsync(fullPath, patchContent.ToString(), cancellationToken);
        return fullPath;
    }
}

