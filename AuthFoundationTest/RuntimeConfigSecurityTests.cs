namespace AuthFoundationTest;

[TestClass]
public sealed class RuntimeConfigSecurityTests
{
    /// <summary>
    /// Development險ｭ螳壹ヵ繧｡繧､繝ｫ縺ｫ鄂ｲ蜷咲畑遘伜ｯ・・ｽ・ｽ縺悟性縺ｾ繧後↑縺・・ｽ・ｽ縺ｨ繧堤｢ｺ隱阪☆繧九・
    /// </summary>
    [TestMethod]
    public void AppSettingsDevelopment_DoesNotContainPrivateSigningKey()
    {
        string appSettings = File.ReadAllText(Path.Combine(FindRepositoryRoot(), "AuthFoundation", "appsettings.Development.json"));

        Assert.IsFalse(appSettings.Contains("BEGIN PRIVATE KEY", StringComparison.Ordinal));
        Assert.IsFalse(appSettings.Contains("SigningKey:PrivateKeyPem", StringComparison.Ordinal));
        Assert.IsFalse(appSettings.Contains("PrivateKeyPem", StringComparison.Ordinal));
    }

    [TestMethod]
    public void LocalRuntimeFiles_DoNotContainCommittedSecrets()
    {
        string root = FindRepositoryRoot();
        string launchSettings = File.ReadAllText(Path.Combine(root, "AuthFoundation", "Properties", "launchSettings.json"));
        string compose = File.ReadAllText(Path.Combine(root, "docker-compose.local.yml"));

        Assert.IsFalse(launchSettings.Contains("BEGIN PRIVATE KEY", StringComparison.Ordinal));
        Assert.IsFalse(compose.Contains("BEGIN PRIVATE KEY", StringComparison.Ordinal));
        Assert.IsFalse(launchSettings.Contains("OsolabAuth_Passw0rd", StringComparison.Ordinal));
        Assert.IsFalse(compose.Contains("OsolabAuth_Passw0rd", StringComparison.Ordinal));
    }

    private static string FindRepositoryRoot()
    {
        DirectoryInfo? current = new(AppContext.BaseDirectory);
        while (current is not null)
        {
            if (Directory.Exists(Path.Combine(current.FullName, "AuthFoundation"))
                && Directory.Exists(Path.Combine(current.FullName, "AuthFoundationTest")))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new DirectoryNotFoundException("repository root was not found.");
    }
}
