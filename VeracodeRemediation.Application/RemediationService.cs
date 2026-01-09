using VeracodeRemediation.Core.Interfaces;
using VeracodeRemediation.Core.Models;

namespace VeracodeRemediation.Application;

/// <summary>
/// Main orchestration service for vulnerability remediation
/// </summary>
public class RemediationService
{
    private readonly IVeracodeApiClient _apiClient;
    private readonly IVulnerabilityClassifier _classifier;
    private readonly IFixEngine _fixEngine;
    private readonly IPatchGenerator _patchGenerator;
    private readonly IReportGenerator _reportGenerator;
    private readonly IConfirmationService? _confirmationService;

    public RemediationService(
        IVeracodeApiClient apiClient,
        IVulnerabilityClassifier classifier,
        IFixEngine fixEngine,
        IPatchGenerator patchGenerator,
        IReportGenerator reportGenerator,
        IConfirmationService? confirmationService = null)
    {
        _apiClient = apiClient;
        _classifier = classifier;
        _fixEngine = fixEngine;
        _patchGenerator = patchGenerator;
        _reportGenerator = reportGenerator;
        _confirmationService = confirmationService;
    }

    public async Task<RemediationReport> RemediateAsync(
        string appGuid,
        string? patchOutputPath = null,
        string? reportOutputPath = null,
        CancellationToken cancellationToken = default)
    {
        // Fetch vulnerabilities
        var sastFindings = await _apiClient.GetSastFindingsAsync(appGuid, cancellationToken);
        var scaFindings = await _apiClient.GetScaFindingsAsync(appGuid, cancellationToken);
        var allVulnerabilities = sastFindings.Concat(scaFindings).ToList();

        var report = new RemediationReport
        {
            TotalVulnerabilities = allVulnerabilities.Count
        };

        var fixResults = new List<FixResult>();

        // Process each vulnerability
        foreach (var vulnerability in allVulnerabilities)
        {
            // Classify
            var canAutoFix = _classifier.CanAutoFix(vulnerability);
            var reason = _classifier.GetClassificationReason(vulnerability);

            if (!canAutoFix)
            {
                report.RequiresManualReview.Add(new VulnerabilitySummary
                {
                    Id = vulnerability.Id,
                    CweId = vulnerability.CweId,
                    Severity = vulnerability.Severity,
                    FilePath = vulnerability.FilePath,
                    Reason = reason
                });
                continue;
            }

            // Check if fix engine can handle it
            if (!_fixEngine.CanFix(vulnerability))
            {
                report.RequiresManualReview.Add(new VulnerabilitySummary
                {
                    Id = vulnerability.Id,
                    CweId = vulnerability.CweId,
                    Severity = vulnerability.Severity,
                    FilePath = vulnerability.FilePath,
                    Reason = "Fix engine cannot handle this vulnerability type"
                });
                continue;
            }

            // Request confirmation before applying fix
            if (_confirmationService != null)
            {
                var fixDescription = $"Auto-fix for {vulnerability.CweId} vulnerability";
                var confirmed = await _confirmationService.ConfirmApplyFixAsync(
                    vulnerability.Id,
                    vulnerability.CweId,
                    vulnerability.FilePath ?? "N/A",
                    fixDescription);

                if (!confirmed)
                {
                    report.RequiresManualReview.Add(new VulnerabilitySummary
                    {
                        Id = vulnerability.Id,
                        CweId = vulnerability.CweId,
                        Severity = vulnerability.Severity,
                        FilePath = vulnerability.FilePath,
                        Reason = "User declined to apply fix"
                    });
                    continue;
                }
            }

            // Apply fix
            var fixResult = await _fixEngine.ApplyFixAsync(vulnerability, cancellationToken);
            fixResults.Add(fixResult);

            if (fixResult.Success)
            {
                report.AutoFixed.Add(new VulnerabilitySummary
                {
                    Id = vulnerability.Id,
                    CweId = vulnerability.CweId,
                    Severity = vulnerability.Severity,
                    FilePath = fixResult.FixedFilePath ?? vulnerability.FilePath,
                    FixDescription = fixResult.Explanation
                });
            }
            else
            {
                report.RequiresManualReview.Add(new VulnerabilitySummary
                {
                    Id = vulnerability.Id,
                    CweId = vulnerability.CweId,
                    Severity = vulnerability.Severity,
                    FilePath = vulnerability.FilePath,
                    Reason = fixResult.ErrorMessage ?? "Fix failed"
                });
            }
        }

        // Generate patch file
        if (fixResults.Any(f => f.Success))
        {
            var patchPath = patchOutputPath ?? "veracode-remediation.patch";
            var successfulFixes = fixResults.Count(f => f.Success);
            
            // Request confirmation before generating patch
            if (_confirmationService != null)
            {
                var confirmed = await _confirmationService.ConfirmGeneratePatchAsync(successfulFixes, patchPath);
                if (!confirmed)
                {
                    Console.WriteLine("⚠️  Patch file generation cancelled by user.");
                }
                else
                {
                    var generatedPatchPath = await _patchGenerator.GeneratePatchFileAsync(
                        fixResults,
                        patchPath,
                        cancellationToken);
                    report.PatchFilePath = generatedPatchPath;
                }
            }
            else
            {
                var generatedPatchPath = await _patchGenerator.GeneratePatchFileAsync(
                    fixResults,
                    patchPath,
                    cancellationToken);
                report.PatchFilePath = generatedPatchPath;
            }
        }

        // Generate report
        var reportPath = reportOutputPath ?? "veracode-remediation-report.md";
        
        // Request confirmation before generating report
        if (_confirmationService != null)
        {
            var confirmed = await _confirmationService.ConfirmGenerateReportAsync(reportPath);
            if (!confirmed)
            {
                Console.WriteLine("⚠️  Report file generation cancelled by user.");
            }
            else
            {
                await _reportGenerator.GenerateReportAsync(report, reportPath, cancellationToken);
            }
        }
        else
        {
            await _reportGenerator.GenerateReportAsync(report, reportPath, cancellationToken);
        }

        return report;
    }
}

