using System.Text.RegularExpressions;
using System.Xml.Linq;
using VeracodeRemediation.Core.Models;

namespace VeracodeRemediation.Application.Fixers;

/// <summary>
/// Fixes SCA vulnerabilities by updating package versions in .csproj files
/// </summary>
public class DependencyFixer : BaseFixer
{
    public async Task<FixResult> FixAsync(Vulnerability vulnerability)
    {
        if (vulnerability.IssueType != "SCA" || 
            string.IsNullOrWhiteSpace(vulnerability.PackageName) ||
            string.IsNullOrWhiteSpace(vulnerability.FixedVersion))
        {
            return new FixResult
            {
                VulnerabilityId = vulnerability.Id,
                Success = false,
                ErrorMessage = "Invalid SCA vulnerability or missing fixed version"
            };
        }

        try
        {
            // Find .csproj files that reference this package
            var csprojFiles = Directory.GetFiles(Directory.GetCurrentDirectory(), "*.csproj", SearchOption.AllDirectories);
            
            foreach (var csprojFile in csprojFiles)
            {
                var content = await ReadFileAsync(csprojFile);
                var originalContent = content;

                // Check if this .csproj references the vulnerable package
                if (content.Contains($"Include=\"{vulnerability.PackageName}\"", StringComparison.OrdinalIgnoreCase))
                {
                    // Update package version using XML parsing
                    var doc = XDocument.Parse(content);
                    var ns = doc.Root?.GetDefaultNamespace() ?? XNamespace.None;
                    
                    var packageRefs = doc.Descendants(ns + "PackageReference")
                        .Where(pr => pr.Attribute("Include")?.Value.Equals(vulnerability.PackageName, StringComparison.OrdinalIgnoreCase) == true);

                    foreach (var packageRef in packageRefs)
                    {
                        var versionAttr = packageRef.Attribute("Version");
                        if (versionAttr != null)
                        {
                            versionAttr.Value = vulnerability.FixedVersion;
                        }
                        else
                        {
                            var versionElement = packageRef.Element(ns + "Version");
                            if (versionElement != null)
                            {
                                versionElement.Value = vulnerability.FixedVersion;
                            }
                            else
                            {
                                packageRef.Add(new XElement(ns + "Version", vulnerability.FixedVersion));
                            }
                        }
                    }

                    var fixedContent = doc.ToString();
                    var patch = GeneratePatch(originalContent, fixedContent, csprojFile);

                    return new FixResult
                    {
                        VulnerabilityId = vulnerability.Id,
                        Success = true,
                        FixedFilePath = csprojFile,
                        PatchContent = patch,
                        Explanation = $"Updated {vulnerability.PackageName} from {vulnerability.PackageVersion} to {vulnerability.FixedVersion}"
                    };
                }
            }

            return new FixResult
            {
                VulnerabilityId = vulnerability.Id,
                Success = false,
                ErrorMessage = $"Could not find .csproj file referencing package {vulnerability.PackageName}"
            };
        }
        catch (Exception ex)
        {
            return new FixResult
            {
                VulnerabilityId = vulnerability.Id,
                Success = false,
                ErrorMessage = $"Error fixing dependency: {ex.Message}"
            };
        }
    }
}

