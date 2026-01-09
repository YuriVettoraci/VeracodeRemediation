using VeracodeRemediation.Application.Fixers;
using VeracodeRemediation.Core.Interfaces;
using VeracodeRemediation.Core.Models;

namespace VeracodeRemediation.Application;

/// <summary>
/// Main fix engine that routes vulnerabilities to appropriate fixers
/// </summary>
public class FixEngine : IFixEngine
{
    private readonly Dictionary<string, Func<Vulnerability, IConfirmationService?, Task<FixResult>>> _fixers;
    private readonly IConfirmationService? _confirmationService;

    public FixEngine(IConfirmationService? confirmationService = null)
    {
        _confirmationService = confirmationService;
        _fixers = new Dictionary<string, Func<Vulnerability, IConfirmationService?, Task<FixResult>>>
        {
            { "CWE-89", async (v, cs) => { var fixer = new SqlInjectionFixer { ConfirmationService = cs }; return await fixer.FixAsync(v); } },
            { "CWE-798", async (v, cs) => { var fixer = new HardcodedSecretFixer { ConfirmationService = cs }; return await fixer.FixAsync(v); } },
            { "CWE-259", async (v, cs) => { var fixer = new HardcodedSecretFixer { ConfirmationService = cs }; return await fixer.FixAsync(v); } },
            { "CWE-327", async (v, cs) => { var fixer = new InsecureHashFixer { ConfirmationService = cs }; return await fixer.FixAsync(v); } },
        };
    }

    public bool CanFix(Vulnerability vulnerability)
    {
        if (vulnerability.IssueType == "SCA" && !string.IsNullOrWhiteSpace(vulnerability.FixedVersion))
        {
            return true;
        }

        return _fixers.ContainsKey(vulnerability.CweId);
    }

    public async Task<FixResult> ApplyFixAsync(Vulnerability vulnerability, CancellationToken cancellationToken = default)
    {
        // Handle SCA vulnerabilities
        if (vulnerability.IssueType == "SCA")
        {
            var dependencyFixer = new DependencyFixer { ConfirmationService = _confirmationService };
            return await dependencyFixer.FixAsync(vulnerability);
        }

        // Handle SAST vulnerabilities
        if (_fixers.TryGetValue(vulnerability.CweId, out var fixer))
        {
            return await fixer(vulnerability, _confirmationService);
        }

        return new FixResult
        {
            VulnerabilityId = vulnerability.Id,
            Success = false,
            ErrorMessage = $"No fixer available for CWE {vulnerability.CweId}",
            RequiresManualReview = true
        };
    }
}

