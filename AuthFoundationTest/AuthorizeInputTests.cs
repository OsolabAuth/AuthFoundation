using AuthFoundation.Controllers.Auth;
using AuthFoundation.Session;
using Microsoft.AspNetCore.Http;

namespace AuthFoundationTest;

[TestClass]
public sealed class AuthorizeInputTests
{
    /// <summary>
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Create を 標準入力 条件で実行
    /// 期待値
    /// 　Reads Authorize Query And Builds Auth Request Session を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
    [TestMethod]
    public void Create_ReadsAuthorizeQueryAndBuildsAuthRequestSession()
    {
        var context = new DefaultHttpContext();
        context.Request.QueryString = QueryString.Create(new Dictionary<string, string?>
        {
            ["response_type"] = "code",
            ["client_id"] = "12345678901234567890123456789012",
            ["redirect_uri"] = "https://client.example.com/callback",
            ["state"] = "state-1",
            ["scope"] = "openid email",
            ["code_challenge_method"] = "S256",
            ["code_challenge"] = new string('a', 43),
            ["nonce"] = "nonce-1"
        });

        AuthorizeController.Input input = AuthorizeController.Input.Create(context);
        input.Validate();
        AuthRequestSession session = input.ToAuthRequestSession();

        Assert.AreEqual("code", session.ResponseType);
        Assert.AreEqual("12345678901234567890123456789012", session.ClientId);
        Assert.AreEqual("https://client.example.com/callback", session.RedirectUri);
        Assert.AreEqual("openid email", session.Scope);
        Assert.AreEqual("S256", session.CodeChallengeMethod);
    }

    /// <summary>
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Validate を 標準入力 条件で実行
    /// 期待値
    /// 　Does Not Duplicate Redirect Uri Format Validation を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
    [TestMethod]
    public void Validate_DoesNotDuplicateRedirectUriFormatValidation()
    {
        var input = new AuthorizeController.Input
        {
            ResponseType = "code",
            ClientId = "12345678901234567890123456789012",
            RedirectUri = "http://example.com/callback",
            State = "state-1",
            Scope = "openid",
            CodeChallengeMethod = "S256",
            CodeChallenge = new string('a', 43),
            Nonce = "nonce-1"
        };

        input.Validate();
    }
}

