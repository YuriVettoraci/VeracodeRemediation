namespace VeracodeRemediation.Core.Entities;

public class FixResult
{
    public bool Success { get; set; }
    public string FilePath { get; set; } = string.Empty;
    public string? ErrorMessage { get; set; }
    public string? PatchContent { get; set; }
    public Vulnerability Vulnerability { get; set; } = null!;
    public string? AppliedFix { get; set; }
}

