using AuthFoundation.Common;
using AuthFoundation.Controllers.Auth;
using AuthFoundation.Services;

namespace AuthFoundationTest;

[TestClass]
public sealed class PasswordResetEndpointShapeTests
{
    /// <summary>
    /// 目的: Reset / Returns Password Reset For Matching Birth Date And Email Code の仕様を検証する。
    /// 入力値: Reset / Returns Password Reset For Matching Birth Date And Email Code を確認するためにテスト内で作成したデータ。
    /// 期待値: メールコード関連のレスポンスと状態が仕様どおりになること。
    /// </summary>
    [TestMethod]
    public void Reset_ReturnsPasswordResetForMatchingBirthDateAndEmailCode()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("reset-endpoint@example.com", "Passw0rd!", "Reset User", new DateOnly(2000, 1, 2));
        var stepUp = new StepUpService(users);
        var controller = CreateController(users, stepUp);
        MfaEmailChallenge challenge = stepUp.StartEmailChallenge("reset-endpoint@example.com");
        var request = new ResetPasswordRequest("reset-endpoint@example.com", "2000-01-02", challenge.Code, "Newpass1!");

        var ok = EndpointTestHelper.AssertOk(controller.Reset(request));

        Assert.AreEqual(200, ok.StatusCode ?? 200);
        Assert.AreEqual("password_reset", EndpointTestHelper.ReadProperty<string>(ok.Value, "result"));
        Assert.AreEqual("Reset User", users.Authenticate("reset-endpoint@example.com", "Newpass1!").Name);
    }

    /// <summary>
    /// 目的: Reset / Returns Bad Request For Invalid Birth Date Format の仕様を検証する。
    /// 入力値: フォーマット不正または権限外の入力値。
    /// 期待値: 400 Bad Request 相当のエラーを返すこと。
    /// </summary>
    [TestMethod]
    public void Reset_ReturnsBadRequestForInvalidBirthDateFormat()
    {
        var users = new InMemoryUserStore();
        var controller = CreateController(users, new StepUpService(users));
        var request = new ResetPasswordRequest("reset-format@example.com", "2000-13-40", "123456", "Newpass1!");

        ErrorOutput error = EndpointTestHelper.AssertError(controller.Reset(request), 400);

        Assert.AreEqual("00001", error.ResponseCode);
        Assert.AreEqual("invalid_request", error.Error);
        Assert.AreEqual("some of the input values are incorrect", error.ErrorDescription);
    }

    /// <summary>
    /// 目的: Reset / Returns Bad Request For Missing Email Code の仕様を検証する。
    /// 入力値: 必須項目または認証ヘッダーを欠落させた入力値。
    /// 期待値: 400 Bad Request 相当のエラーを返すこと。
    /// </summary>
    [TestMethod]
    public void Reset_ReturnsBadRequestForMissingEmailCode()
    {
        var users = new InMemoryUserStore();
        var controller = CreateController(users, new StepUpService(users));
        var request = new ResetPasswordRequest("reset-missing-code@example.com", "1990-01-01", string.Empty, "Newpass1!");

        ErrorOutput error = EndpointTestHelper.AssertError(controller.Reset(request), 400);

        Assert.AreEqual("00001", error.ResponseCode);
        Assert.AreEqual("invalid_request", error.Error);
        Assert.AreEqual("email_code is required", error.ErrorDescription);
    }

    /// <summary>
    /// 目的: Reset / Returns Unauthorized For Mismatched Birth Date の仕様を検証する。
    /// 入力値: Reset / Returns Unauthorized For Mismatched Birth Date を確認するためにテスト内で作成したデータ。
    /// 期待値: 401 Unauthorized と invalid_token 系のエラーを返すこと。
    /// </summary>
    [TestMethod]
    public void Reset_ReturnsUnauthorizedForMismatchedBirthDate()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("reset-mismatch@example.com", "Passw0rd!", "Reset User", new DateOnly(2000, 1, 2));
        var stepUp = new StepUpService(users);
        var controller = CreateController(users, stepUp);
        MfaEmailChallenge challenge = stepUp.StartEmailChallenge("reset-mismatch@example.com");
        var request = new ResetPasswordRequest("reset-mismatch@example.com", "2001-01-02", challenge.Code, "Newpass1!");

        ErrorOutput error = EndpointTestHelper.AssertError(controller.Reset(request), 401);

        Assert.AreEqual("00008", error.ResponseCode);
        Assert.AreEqual("invalid_token", error.Error);
        Assert.AreEqual("Reset User", users.Authenticate("reset-mismatch@example.com", "Passw0rd!").Name);
    }

    /// <summary>
    /// 目的: Reset / Returns Unauthorized For Wrong Email Code の仕様を検証する。
    /// 入力値: 正しい主体に紐づかない誤った認証情報。
    /// 期待値: 401 Unauthorized と invalid_token 系のエラーを返すこと。
    /// </summary>
    [TestMethod]
    public void Reset_ReturnsUnauthorizedForWrongEmailCode()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("reset-wrong-code@example.com", "Passw0rd!", "Reset User", new DateOnly(2000, 1, 2));
        var stepUp = new StepUpService(users);
        var controller = CreateController(users, stepUp);
        MfaEmailChallenge challenge = stepUp.StartEmailChallenge("reset-wrong-code@example.com");
        var request = new ResetPasswordRequest("reset-wrong-code@example.com", "2000-01-02", DifferentCode(challenge.Code), "Newpass1!");

        ErrorOutput error = EndpointTestHelper.AssertError(controller.Reset(request), 401);

        Assert.AreEqual("00008", error.ResponseCode);
        Assert.AreEqual("invalid_token", error.Error);
        Assert.AreEqual("Reset User", users.Authenticate("reset-wrong-code@example.com", "Passw0rd!").Name);
    }

    /// <summary>
    /// 目的: Reset / Returns Bad Request For Weak New Password の仕様を検証する。
    /// 入力値: Reset / Returns Bad Request For Weak New Password を確認するためにテスト内で作成したデータ。
    /// 期待値: 400 Bad Request 相当のエラーを返すこと。
    /// </summary>
    [TestMethod]
    public void Reset_ReturnsBadRequestForWeakNewPassword()
    {
        var users = new InMemoryUserStore();
        var controller = CreateController(users, new StepUpService(users));
        var request = new ResetPasswordRequest("reset-weak@example.com", "2000-01-02", "123456", "weak");

        ErrorOutput error = EndpointTestHelper.AssertError(controller.Reset(request), 400);

        Assert.AreEqual("00001", error.ResponseCode);
        Assert.AreEqual("invalid_request", error.Error);
        Assert.AreEqual("password is invalid", error.ErrorDescription);
    }

    private static PasswordController CreateController(InMemoryUserStore users, StepUpService stepUp)
    {
        return EndpointTestHelper.WithHttpContext(new PasswordController(users, stepUp));
    }

    private static string DifferentCode(string code)
    {
        return string.Equals(code, "000000", StringComparison.Ordinal) ? "000001" : "000000";
    }
}
