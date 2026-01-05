using VeracodeRemediation.Core.Models;

namespace VeracodeRemediation.Core.Interfaces;

/// <summary>
/// Generates remediation reports
/// </summary>
public interface IReportGenerator
{
    Task<string> GenerateReportAsync(
        RemediationReport report,
        string outputPath,
        CancellationToken cancellationToken = default);
}
