using System.Text;
using System.Text.RegularExpressions;
using VeracodeRemediation.Core.Interfaces;
using VeracodeRemediation.Core.Models;

namespace VeracodeRemediation.Application.Fixers;

/// <summary>
/// Base class for vulnerability fixers
/// </summary>
public abstract class BaseFixer
{
    public IConfirmationService? ConfirmationService { get; set; }

    protected async Task<string> ReadFileAsync(string filePath)
    {
        // Request confirmation before reading file
        if (ConfirmationService != null)
        {
            var confirmed = await ConfirmationService.ConfirmReadFileAsync(filePath);
            if (!confirmed)
            {
                throw new UnauthorizedAccessException($"User declined to read file: {filePath}");
            }
        }

        if (!File.Exists(filePath))
            throw new FileNotFoundException($"File not found: {filePath}");

        return await File.ReadAllTextAsync(filePath);
    }

    protected static async Task WriteFileAsync(string filePath, string content)
    {
        var directory = Path.GetDirectoryName(filePath);
        if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
        {
            Directory.CreateDirectory(directory);
        }

        await File.WriteAllTextAsync(filePath, content, Encoding.UTF8);
    }

    protected static string GeneratePatch(string originalContent, string fixedContent, string filePath)
    {
        var originalLines = originalContent.Split('\n');
        var fixedLines = fixedContent.Split('\n');
        
        var patch = new StringBuilder();
        patch.AppendLine($"--- a/{filePath}");
        patch.AppendLine($"+++ b/{filePath}");
        
        var diff = ComputeDiff(originalLines, fixedLines);
        foreach (var hunk in diff)
        {
            patch.AppendLine(hunk);
        }
        
        return patch.ToString();
    }

    private static List<string> ComputeDiff(string[] original, string[] fixedContent)
    {
        // Simplified diff algorithm - in production, use a proper diff library
        var hunks = new List<string>();
        var i = 0;
        var j = 0;
        var contextStart = -1;

        while (i < original.Length || j < fixedContent.Length)
        {
            if (i < original.Length && j < fixedContent.Length && original[i] == fixedContent[j])
            {
                i++;
                j++;
            }
            else
            {
                if (contextStart == -1)
                {
                    contextStart = Math.Max(0, i - 3);
                    hunks.Add($"@@ -{contextStart + 1},{original.Length - contextStart} +{contextStart + 1},{fixedContent.Length - contextStart} @@");
                }

                if (i < original.Length)
                {
                    hunks.Add($"-{original[i]}");
                    i++;
                }

                if (j < fixedContent.Length)
                {
                    hunks.Add($"+{fixedContent[j]}");
                    j++;
                }
            }
        }

        return hunks;
    }
}

