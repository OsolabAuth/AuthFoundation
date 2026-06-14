namespace AuthFoundationTest;

[TestClass]
public sealed class SqlUserStoreQueryShapeTests
{
    /// <summary>
    /// Purpose: verify that the SQL user store still reads the legacy birthdate key.
    /// Input: SqlUserStore source code.
    /// Expected: the birth date projection accepts both birth_date and birthdate.
    /// </summary>
    [TestMethod]
    public void FindByEmail_ReadsLegacyBirthdateKey()
    {
        string source = File.ReadAllText(Path.Combine("..", "..", "..", "..", "AuthFoundation", "Services", "SqlUserStore.cs"));

        StringAssert.Contains(source, "ui.[data_key] IN ('birth_date', 'birthdate')");
    }
}
