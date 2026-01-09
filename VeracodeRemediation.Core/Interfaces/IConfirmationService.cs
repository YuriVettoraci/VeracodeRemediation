namespace VeracodeRemediation.Core.Interfaces;

/// <summary>
/// Service for requesting user confirmation before performing security-sensitive operations
/// </summary>
public interface IConfirmationService
{
    /// <summary>
    /// Requests confirmation before connecting to Veracode API
    /// </summary>
    Task<bool> ConfirmApiConnectionAsync(string apiId, string applicationName);

    /// <summary>
    /// Requests confirmation before fetching vulnerabilities from Veracode
    /// </summary>
    Task<bool> ConfirmFetchVulnerabilitiesAsync(string applicationName, string appGuid);

    /// <summary>
    /// Requests confirmation before applying a fix to a vulnerability
    /// </summary>
    Task<bool> ConfirmApplyFixAsync(string vulnerabilityId, string cweId, string filePath, string fixDescription);

    /// <summary>
    /// Requests confirmation before generating a patch file
    /// </summary>
    Task<bool> ConfirmGeneratePatchAsync(int fixCount, string patchPath);

    /// <summary>
    /// Requests confirmation before generating a report file
    /// </summary>
    Task<bool> ConfirmGenerateReportAsync(string reportPath);

    /// <summary>
    /// Requests confirmation before reading a file from the filesystem
    /// </summary>
    Task<bool> ConfirmReadFileAsync(string filePath);

    /// <summary>
    /// Requests confirmation before modifying a file
    /// </summary>
    Task<bool> ConfirmModifyFileAsync(string filePath, string changeDescription);
}
