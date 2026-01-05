using VeracodeRemediation.Core.Models;

namespace VeracodeRemediation.Core.Interfaces;

/// <summary>
/// Client for interacting with Veracode API
/// </summary>
public interface IVeracodeApiClient
{
    Task<List<Vulnerability>> GetSastFindingsAsync(string appGuid, CancellationToken cancellationToken = default);
    Task<List<Vulnerability>> GetScaFindingsAsync(string appGuid, CancellationToken cancellationToken = default);
    Task<List<string>> GetApplicationGuidsAsync(CancellationToken cancellationToken = default);
    Task<string?> GetApplicationGuidByNameAsync(string appName, CancellationToken cancellationToken = default);
}
