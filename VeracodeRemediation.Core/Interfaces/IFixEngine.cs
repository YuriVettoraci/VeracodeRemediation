using VeracodeRemediation.Core.Models;

namespace VeracodeRemediation.Core.Interfaces;

/// <summary>
/// Engine for applying automated fixes to vulnerabilities
/// </summary>
public interface IFixEngine
{
    Task<FixResult> ApplyFixAsync(Vulnerability vulnerability, CancellationToken cancellationToken = default);
    bool CanFix(Vulnerability vulnerability);
}
