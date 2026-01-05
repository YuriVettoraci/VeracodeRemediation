namespace VeracodeRemediation.Core.Models;

/// <summary>
/// Comprehensive remediation report
/// </summary>
public class RemediationReport
{
    public DateTime GeneratedAt { get; set; } = DateTime.UtcNow;
    public List<VulnerabilitySummary> AutoFixed { get; set; } = new();
    public List<VulnerabilitySummary> RequiresManualReview { get; set; } = new();
    public List<VulnerabilitySummary> Skipped { get; set; } = new();
    public int TotalVulnerabilities { get; set; }
    public string? PatchFilePath { get; set; }
}

public class VulnerabilitySummary
{
    public string Id { get; set; } = string.Empty;
    public string CweId { get; set; } = string.Empty;
    public string Severity { get; set; } = string.Empty;
    public string FilePath { get; set; } = string.Empty;
    public string? Reason { get; set; }
    public string? FixDescription { get; set; }
}

