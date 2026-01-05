using System.Text;
using VeracodeRemediation.Core.Entities;
using VeracodeRemediation.Core.Interfaces;

namespace VeracodeRemediation.Application.Services;

public class ReportGenerator : IReportGenerator
{
    public async Task<string> GenerateRemediationReportAsync(
        List<Vulnerability> vulnerabilities,
        List<FixResult> fixResults)
    {
        var report = new StringBuilder();
        
        report.AppendLine("# Veracode Security Remediation Report");
        report.AppendLine($"**Generated:** {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC");
        report.AppendLine();

        // Summary
        report.AppendLine("## Executive Summary");
        report.AppendLine();
        report.AppendLine($"- **Total Vulnerabilities:** {vulnerabilities.Count}");
        report.AppendLine($"- **Auto-Fixed:** {fixResults.Count(r => r.Success)}");
        report.AppendLine($"- **Requires Manual Review:** {vulnerabilities.Count - fixResults.Count(r => r.Success)}");
        report.AppendLine();

        // Breakdown by severity
        var severityBreakdown = vulnerabilities.GroupBy(v => v.Severity)
            .OrderByDescending(g => g.Key == "Critical" ? 4 : g.Key == "High" ? 3 : g.Key == "Medium" ? 2 : 1);
        
        report.AppendLine("### Severity Breakdown");
        report.AppendLine();
        foreach (var group in severityBreakdown)
        {
            report.AppendLine($"- **{group.Key}:** {group.Count()}");
        }
        report.AppendLine();

        // Breakdown by type
        var typeBreakdown = vulnerabilities.GroupBy(v => v.VulnerabilityType);
        report.AppendLine("### Vulnerability Type Breakdown");
        report.AppendLine();
        foreach (var group in typeBreakdown)
        {
            report.AppendLine($"- **{group.Key}:** {group.Count()}");
        }
        report.AppendLine();

        // Auto-fixed vulnerabilities
        var autoFixed = fixResults.Where(r => r.Success).ToList();
        if (autoFixed.Any())
        {
            report.AppendLine("## Automatically Fixed Vulnerabilities");
            report.AppendLine();
            
            foreach (var result in autoFixed)
            {
                var vuln = result.Vulnerability;
                report.AppendLine($"### {vuln.CweId} - {vuln.IssueId}");
                report.AppendLine();
                report.AppendLine($"- **Severity:** {vuln.Severity}");
                report.AppendLine($"- **Type:** {vuln.VulnerabilityType}");
                report.AppendLine($"- **File:** `{vuln.FilePath}`");
                if (vuln.LineNumber.HasValue)
                {
                    report.AppendLine($"- **Line:** {vuln.LineNumber.Value}");
                }
                report.AppendLine($"- **Description:** {vuln.Description}");
                report.AppendLine($"- **Applied Fix:** {result.AppliedFix}");
                report.AppendLine();
            }
        }

        // Manual review required
        var manualReview = vulnerabilities
            .Where(v => !fixResults.Any(r => r.Success && r.Vulnerability.Id == v.Id))
            .ToList();
        
        if (manualReview.Any())
        {
            report.AppendLine("## Vulnerabilities Requiring Manual Review");
            report.AppendLine();
            
            foreach (var vuln in manualReview)
            {
                report.AppendLine($"### {vuln.CweId} - {vuln.IssueId}");
                report.AppendLine();
                report.AppendLine($"- **Severity:** {vuln.Severity}");
                report.AppendLine($"- **Type:** {vuln.VulnerabilityType}");
                report.AppendLine($"- **File:** `{vuln.FilePath ?? "N/A"}`");
                if (vuln.LineNumber.HasValue)
                {
                    report.AppendLine($"- **Line:** {vuln.LineNumber.Value}");
                }
                report.AppendLine($"- **Description:** {vuln.Description}");
                report.AppendLine($"- **Reason for Manual Review:** {vuln.AutoFixReason ?? "Not classified as auto-fixable"}");
                
                if (!string.IsNullOrEmpty(vuln.RemediationGuidance))
                {
                    report.AppendLine($"- **Veracode Remediation Guidance:** {vuln.RemediationGuidance}");
                }
                
                if (vuln.VulnerabilityType == "SCA" && !string.IsNullOrEmpty(vuln.FixedVersion))
                {
                    report.AppendLine($"- **Recommended Action:** Upgrade {vuln.PackageName} from {vuln.PackageVersion} to {vuln.FixedVersion}");
                }
                
                report.AppendLine();
            }
        }

        // SCA dependency updates
        var scaVulns = vulnerabilities.Where(v => v.VulnerabilityType == "SCA").ToList();
        if (scaVulns.Any())
        {
            report.AppendLine("## SCA Dependency Updates");
            report.AppendLine();
            report.AppendLine("The following package updates are recommended:");
            report.AppendLine();
            
            foreach (var vuln in scaVulns.Where(v => !string.IsNullOrEmpty(v.FixedVersion)))
            {
                report.AppendLine($"- **{vuln.PackageName}:** {vuln.PackageVersion} → {vuln.FixedVersion} ({vuln.Severity})");
            }
            report.AppendLine();
        }

        // Veracode links
        report.AppendLine("## Veracode Links");
        report.AppendLine();
        report.AppendLine("For detailed information about these vulnerabilities, visit:");
        report.AppendLine("- [Veracode Platform](https://analysiscenter.veracode.com/)");
        report.AppendLine();

        return report.ToString();
    }

    public async Task SaveReportAsync(string reportContent, string outputPath)
    {
        var directory = Path.GetDirectoryName(outputPath);
        if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
        {
            Directory.CreateDirectory(directory);
        }

        await File.WriteAllTextAsync(outputPath, reportContent);
    }
}

