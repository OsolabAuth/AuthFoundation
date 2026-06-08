namespace AuthFoundationTest;

[TestClass]
public sealed class RuntimeConfigSecurityTests
{
    /// <summary>
    /// Development設定ファイルに署名用秘密鍵が含まれないことを確認する。
    /// </summary>
    [TestMethod]
    public void AppSettingsDevelopment_DoesNotContainPrivateSigningKey()
    {
        string appSettings = File.ReadAllText(Path.Combine(FindRepositoryRoot(), "AuthFoundation", "appsettings.Development.json"));

        Assert.IsFalse(appSettings.Contains("BEGIN PRIVATE KEY", StringComparison.Ordinal));
        Assert.IsFalse(appSettings.Contains("SigningKey:PrivateKeyPem", StringComparison.Ordinal));
        Assert.IsFalse(appSettings.Contains("PrivateKeyPem", StringComparison.Ordinal));
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
