using VeracodeRemediation.Core.Models;

namespace VeracodeRemediation.Core.Interfaces;

/// <summary>
/// Generates patch files from fix results
/// </summary>
public interface IPatchGenerator
{
    Task<string> GeneratePatchFileAsync(List<FixResult> fixResults, string outputPath, CancellationToken cancellationToken = default);
}
