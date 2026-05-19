using AuthFoundation.Common;
using AuthFoundationTest.TestSupport;
using Microsoft.EntityFrameworkCore;

namespace AuthFoundationTest;

[TestClass]
public sealed class DatabaseSeedTests
{
    [TestMethod]
    public async Task InitializedSqlFolderData_ContainsDefaultClientAndScopes()
    {
        await using var context = TestDbContextFactory.Create();
        Assert.IsTrue(
            await context.Database.CanConnectAsync(),
            "SQL Server is not available. Run the SQL folder initialization before this test.");

        bool innerClientExists = await context.client_masters.AnyAsync(x =>
            x.client_id == Code.InnerClient.OSOLAB_CLIENT_ID
            && x.status == Code.Status.ACTIVE);

        string[] scopes = await context.scope_masters
            .OrderBy(x => x.scope)
            .Select(x => x.scope)
            .ToArrayAsync();

        Assert.IsTrue(innerClientExists);
        CollectionAssert.IsSubsetOf(new[] { "email", "openid", "profile" }, scopes);
    }
}
