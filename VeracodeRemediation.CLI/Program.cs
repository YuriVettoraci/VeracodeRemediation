using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using VeracodeRemediation.Application;
using VeracodeRemediation.Application.Classifiers;
using VeracodeRemediation.Application.Generators;
using VeracodeRemediation.Application.Services;
using VeracodeRemediation.Core.Interfaces;
using VeracodeRemediation.Infrastructure.Veracode;

namespace VeracodeRemediation.CLI;

class Program
{
    static async Task Main(string[] args)
    {
        var host = CreateHostBuilder(args).Build();
        var logger = host.Services.GetRequiredService<ILogger<Program>>();

        try
        {
            // Parse command line arguments
            var config = host.Services.GetRequiredService<IConfiguration>();
            var apiId = config["Veracode:ApiId"] ?? Environment.GetEnvironmentVariable("Veracode__ApiId") ?? Environment.GetEnvironmentVariable("VERACODE_API_ID");
            var apiKey = config["Veracode:ApiKey"] ?? Environment.GetEnvironmentVariable("Veracode__ApiKey") ?? Environment.GetEnvironmentVariable("VERACODE_API_KEY");
            var appName = args.Length > 0 ? args[0] : config["Veracode:ApplicationName"];
            var appGuid = args.Length > 1 ? args[1] : null;
            var patchPath = args.Length > 2 ? args[2] : "veracode-remediation.patch";
            var reportPath = args.Length > 3 ? args[3] : "veracode-remediation-report.md";

            if (string.IsNullOrWhiteSpace(apiId) || string.IsNullOrWhiteSpace(apiKey))
            {
                logger.LogError("Veracode API credentials not found. Set Veracode__ApiId and Veracode__ApiKey environment variables (or VERACODE_API_ID and VERACODE_API_KEY) or configure in appsettings.json");
                return;
            }

            if (string.IsNullOrWhiteSpace(appName) && string.IsNullOrWhiteSpace(appGuid))
            {
                logger.LogError("Application name or GUID must be provided as first argument or configured in appsettings.json");
                logger.LogInformation("Usage: VeracodeRemediation.CLI <app-name-or-guid> [patch-path] [report-path]");
                return;
            }

            var confirmationService = host.Services.GetRequiredService<IConfirmationService>();
            var apiClient = new VeracodeApiClient(apiId, apiKey);
            var remediationService = host.Services.GetRequiredService<RemediationService>();

            // Request confirmation before connecting to API
            var finalAppName = appName ?? "Unknown Application";
            var confirmed = await confirmationService.ConfirmApiConnectionAsync(apiId, finalAppName);
            if (!confirmed)
            {
                logger.LogWarning("API connection cancelled by user.");
                return;
            }

            // Resolve application GUID if name provided
            if (!string.IsNullOrWhiteSpace(appName) && string.IsNullOrWhiteSpace(appGuid))
            {
                logger.LogInformation($"Looking up application GUID for: {appName}");
                appGuid = await apiClient.GetApplicationGuidByNameAsync(appName);
                if (string.IsNullOrWhiteSpace(appGuid))
                {
                    logger.LogError($"Application '{appName}' not found");
                    return;
                }
                logger.LogInformation($"Found application GUID: {appGuid}");
            }

            // Request confirmation before fetching vulnerabilities
            confirmed = await confirmationService.ConfirmFetchVulnerabilitiesAsync(
                finalAppName,
                appGuid ?? "N/A");
            if (!confirmed)
            {
                logger.LogWarning("Vulnerability fetch cancelled by user.");
                return;
            }

            logger.LogInformation("Starting vulnerability remediation...");
            logger.LogInformation($"Application GUID: {appGuid}");

            var report = await remediationService.RemediateAsync(
                appGuid!,
                patchPath,
                reportPath);

            logger.LogInformation("Remediation completed!");
            logger.LogInformation($"Auto-fixed: {report.AutoFixed.Count}");
            logger.LogInformation($"Requires manual review: {report.RequiresManualReview.Count}");
            logger.LogInformation($"Skipped: {report.Skipped.Count}");
            logger.LogInformation($"Patch file: {report.PatchFilePath}");
            logger.LogInformation($"Report file: {reportPath}");
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "An error occurred during remediation");
            Environment.Exit(1);
        }
    }

    static IHostBuilder CreateHostBuilder(string[] args) =>
        Host.CreateDefaultBuilder(args)
            .ConfigureAppConfiguration((context, config) =>
            {
                // Host.CreateDefaultBuilder already adds appsettings.json, but we ensure it's loaded
                // and add environment variables support
                config.AddEnvironmentVariables();
            })
            .ConfigureServices((context, services) =>
            {
                var configuration = context.Configuration;
                var apiId = configuration["Veracode:ApiId"] ?? Environment.GetEnvironmentVariable("Veracode__ApiId") ?? Environment.GetEnvironmentVariable("VERACODE_API_ID") ?? "";
                var apiKey = configuration["Veracode:ApiKey"] ?? Environment.GetEnvironmentVariable("Veracode__ApiKey") ?? Environment.GetEnvironmentVariable("VERACODE_API_KEY") ?? "";

                services.AddHttpClient();
                services.AddSingleton<IVeracodeApiClient>(sp => new VeracodeApiClient(apiId, apiKey));
                services.AddSingleton<IVulnerabilityClassifier, VulnerabilityClassifier>();
                services.AddSingleton<IConfirmationService, ConfirmationService>();
                services.AddSingleton<IFixEngine>(sp => new FixEngine(sp.GetService<IConfirmationService>()));
                services.AddSingleton<IPatchGenerator, PatchGenerator>();
                services.AddSingleton<IReportGenerator, ReportGenerator>();
                services.AddSingleton<RemediationService>(sp => new RemediationService(
                    sp.GetRequiredService<IVeracodeApiClient>(),
                    sp.GetRequiredService<IVulnerabilityClassifier>(),
                    sp.GetRequiredService<IFixEngine>(),
                    sp.GetRequiredService<IPatchGenerator>(),
                    sp.GetRequiredService<IReportGenerator>(),
                    sp.GetService<IConfirmationService>()));
            })
            .ConfigureLogging(logging =>
            {
                logging.ClearProviders();
                logging.AddConsole();
                logging.SetMinimumLevel(LogLevel.Information);
            });
}
