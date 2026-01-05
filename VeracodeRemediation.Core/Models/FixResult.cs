namespace VeracodeRemediation.Core.Models;

/// <summary>
/// Result of an automated fix attempt
/// </summary>
public class FixResult
{
    public string VulnerabilityId { get; set; } = string.Empty;
    public bool Success { get; set; }
    public string? ErrorMessage { get; set; }
    public string? FixedFilePath { get; set; }
    public string? PatchContent { get; set; }
    public string? Explanation { get; set; }
    public bool RequiresManualReview { get; set; }
}

