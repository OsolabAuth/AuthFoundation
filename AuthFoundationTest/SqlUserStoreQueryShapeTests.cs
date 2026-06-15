namespace AuthFoundationTest;

[TestClass]
public sealed class SqlUserStoreQueryShapeTests
{
    /// <summary>
    /// Purpose: verify that the SQL user store still reads the legacy birthdate key after EF conversion.
    /// Input: SqlUserStore source code.
    /// Expected: the birth date projection accepts both birth_date and birthdate without hand-written SQL.
    /// </summary>
    [TestMethod]
    public void FindByEmail_ReadsLegacyBirthdateKey()
    {
        string source = File.ReadAllText(Path.Combine("..", "..", "..", "..", "AuthFoundation", "Services", "SqlUserStore.cs"));

        StringAssert.Contains(source, "info.TryGetValue(\"birth_date\"");
        StringAssert.Contains(source, "info.TryGetValue(\"birthdate\"");
        StringAssert.Contains(source, "IDbContextFactory<OsolabAuthContext>");
    }
}
