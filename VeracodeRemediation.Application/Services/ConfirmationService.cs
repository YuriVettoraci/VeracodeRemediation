using VeracodeRemediation.Core.Interfaces;

namespace VeracodeRemediation.Application.Services;

/// <summary>
/// Interactive confirmation service that prompts user for approval before security-sensitive operations
/// </summary>
public class ConfirmationService : IConfirmationService
{
    public async Task<bool> ConfirmApiConnectionAsync(string apiId, string applicationName)
    {
        Console.WriteLine();
        Console.WriteLine("⚠️  SECURITY CONFIRMATION REQUIRED");
        Console.WriteLine("═══════════════════════════════════════════════════════════");
        Console.WriteLine($"The application will connect to Veracode API using:");
        Console.WriteLine($"  • API ID: {MaskSensitiveData(apiId)}");
        Console.WriteLine($"  • Application: {applicationName}");
        Console.WriteLine();
        Console.WriteLine("This will authenticate and access Veracode security data.");
        Console.WriteLine("═══════════════════════════════════════════════════════════");
        
        return await PromptConfirmationAsync("Do you want to proceed with API connection?");
    }

    public async Task<bool> ConfirmFetchVulnerabilitiesAsync(string applicationName, string appGuid)
    {
        Console.WriteLine();
        Console.WriteLine("⚠️  SECURITY CONFIRMATION REQUIRED");
        Console.WriteLine("═══════════════════════════════════════════════════════════");
        Console.WriteLine($"The application will fetch vulnerability data from:");
        Console.WriteLine($"  • Application: {applicationName}");
        Console.WriteLine($"  • Application GUID: {appGuid}");
        Console.WriteLine();
        Console.WriteLine("This will retrieve SAST and SCA findings from Veracode.");
        Console.WriteLine("═══════════════════════════════════════════════════════════");
        
        return await PromptConfirmationAsync("Do you want to proceed with fetching vulnerabilities?");
    }

    public async Task<bool> ConfirmApplyFixAsync(string vulnerabilityId, string cweId, string filePath, string fixDescription)
    {
        Console.WriteLine();
        Console.WriteLine("⚠️  SECURITY CONFIRMATION REQUIRED");
        Console.WriteLine("═══════════════════════════════════════════════════════════");
        Console.WriteLine($"The application will generate a fix for:");
        Console.WriteLine($"  • Vulnerability ID: {vulnerabilityId}");
        Console.WriteLine($"  • CWE: {cweId}");
        Console.WriteLine($"  • File: {filePath}");
        Console.WriteLine($"  • Fix: {fixDescription}");
        Console.WriteLine();
        Console.WriteLine("⚠️  WARNING: This will modify code to address a security vulnerability.");
        Console.WriteLine("═══════════════════════════════════════════════════════════");
        
        return await PromptConfirmationAsync($"Do you want to generate a fix for {cweId} in {Path.GetFileName(filePath)}?");
    }

    public async Task<bool> ConfirmGeneratePatchAsync(int fixCount, string patchPath)
    {
        Console.WriteLine();
        Console.WriteLine("⚠️  SECURITY CONFIRMATION REQUIRED");
        Console.WriteLine("═══════════════════════════════════════════════════════════");
        Console.WriteLine($"The application will generate a patch file containing:");
        Console.WriteLine($"  • Total fixes: {fixCount}");
        Console.WriteLine($"  • Output path: {patchPath}");
        Console.WriteLine();
        Console.WriteLine("⚠️  WARNING: This patch file will contain code changes.");
        Console.WriteLine("   Review the patch carefully before applying it.");
        Console.WriteLine("═══════════════════════════════════════════════════════════");
        
        return await PromptConfirmationAsync($"Do you want to generate the patch file with {fixCount} fix(es)?");
    }

    public async Task<bool> ConfirmGenerateReportAsync(string reportPath)
    {
        Console.WriteLine();
        Console.WriteLine("ℹ️  CONFIRMATION REQUIRED");
        Console.WriteLine("═══════════════════════════════════════════════════════════");
        Console.WriteLine($"The application will generate a remediation report:");
        Console.WriteLine($"  • Output path: {reportPath}");
        Console.WriteLine();
        Console.WriteLine("This report will contain vulnerability analysis and fix summaries.");
        Console.WriteLine("═══════════════════════════════════════════════════════════");
        
        return await PromptConfirmationAsync("Do you want to generate the remediation report?");
    }

    public async Task<bool> ConfirmReadFileAsync(string filePath)
    {
        Console.WriteLine();
        Console.WriteLine("⚠️  SECURITY CONFIRMATION REQUIRED");
        Console.WriteLine("═══════════════════════════════════════════════════════════");
        Console.WriteLine($"The application needs to read a file:");
        Console.WriteLine($"  • File: {filePath}");
        Console.WriteLine();
        Console.WriteLine("This is required to analyze and fix vulnerabilities.");
        Console.WriteLine("═══════════════════════════════════════════════════════════");
        
        return await PromptConfirmationAsync($"Do you want to allow reading {Path.GetFileName(filePath)}?");
    }

    public async Task<bool> ConfirmModifyFileAsync(string filePath, string changeDescription)
    {
        Console.WriteLine();
        Console.WriteLine("⚠️  SECURITY CONFIRMATION REQUIRED");
        Console.WriteLine("═══════════════════════════════════════════════════════════");
        Console.WriteLine($"The application wants to modify a file:");
        Console.WriteLine($"  • File: {filePath}");
        Console.WriteLine($"  • Change: {changeDescription}");
        Console.WriteLine();
        Console.WriteLine("⚠️  WARNING: This will modify source code files.");
        Console.WriteLine("═══════════════════════════════════════════════════════════");
        
        return await PromptConfirmationAsync($"Do you want to allow modification of {Path.GetFileName(filePath)}?");
    }

    private static async Task<bool> PromptConfirmationAsync(string message)
    {
        Console.Write($"{message} (yes/no): ");
        var response = Console.ReadLine()?.Trim().ToLowerInvariant();
        
        // Retry if invalid input
        while (response != "yes" && response != "y" && response != "no" && response != "n")
        {
            Console.Write("Please enter 'yes' or 'no': ");
            response = Console.ReadLine()?.Trim().ToLowerInvariant();
        }

        var confirmed = response == "yes" || response == "y";
        
        if (confirmed)
        {
            Console.WriteLine("✅ Confirmed. Proceeding...");
        }
        else
        {
            Console.WriteLine("❌ Cancelled by user.");
        }
        
        Console.WriteLine();
        
        return await Task.FromResult(confirmed);
    }

    private static string MaskSensitiveData(string data)
    {
        if (string.IsNullOrWhiteSpace(data) || data.Length <= 8)
            return "***";
        
        return $"{data.Substring(0, 4)}...{data.Substring(data.Length - 4)}";
    }
}
