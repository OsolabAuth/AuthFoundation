using AuthFoundation.Common;
using AuthFoundationTest.TestSupport;
using Microsoft.EntityFrameworkCore;

namespace AuthFoundationTest;

[TestClass]
public sealed class DatabaseSeedTests
{
    /// <summary>
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Initialized Sql Folder Data を 標準入力 条件で実行
    /// 期待値
    /// 　Contains Default Client And Scopes を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
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
