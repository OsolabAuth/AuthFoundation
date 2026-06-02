using AuthFoundation.Common;
using AuthFoundation.Controllers.Auth;
using AuthFoundation.Services;

namespace AuthFoundationTest;

[TestClass]
public sealed class AccountWithdrawalEndpointShapeTests
{
    /// <summary>
    /// 目的: Withdraw / Returns Account Withdrawn With Valid Step Up の仕様を検証する。
    /// 入力値: テスト内で登録した正常な対象データ。
    /// 期待値: Withdraw / Returns Account Withdrawn With Valid Step Up の期待結果になること。
    /// </summary>
    [TestMethod]
    public void Withdraw_ReturnsAccountWithdrawnWithValidStepUp()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("withdraw-endpoint@example.com", "Passw0rd!", "Withdraw User", new DateOnly(2000, 1, 1), "withdraw_subject");
        var stepUp = new StepUpService(users);
        StepUpGrant grant = IssueEmailStepUp(stepUp, "withdraw-endpoint@example.com");
        var controller = EndpointTestHelper.WithHttpContext(new AccountController(users, stepUp));
        var request = new WithdrawalRequest("withdraw-endpoint@example.com", "Passw0rd!", grant.StepUpToken);

        var ok = EndpointTestHelper.AssertOk(controller.Withdraw(request));

        Assert.AreEqual(200, ok.StatusCode ?? 200);
        Assert.AreEqual("account_withdrawn", EndpointTestHelper.ReadProperty<string>(ok.Value, "result"));
        Assert.ThrowsExactly<ApiException>(() => users.FindByEmail("withdraw-endpoint@example.com"));
    }

    /// <summary>
    /// 目的: Withdraw / Returns Unauthorized For Missing Step Up Grant の仕様を検証する。
    /// 入力値: 必須項目または認証ヘッダーを欠落させた入力値。
    /// 期待値: 401 Unauthorized と invalid_token 系のエラーを返すこと。
    /// </summary>
    [TestMethod]
    public void Withdraw_ReturnsUnauthorizedForMissingStepUpGrant()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("withdraw-no-step@example.com", "Passw0rd!", "Withdraw User", new DateOnly(2000, 1, 1));
        var controller = EndpointTestHelper.WithHttpContext(new AccountController(users, new StepUpService(users)));
        var request = new WithdrawalRequest("withdraw-no-step@example.com", "Passw0rd!", "sup_missing");

        ErrorOutput error = EndpointTestHelper.AssertError(controller.Withdraw(request), 401);

        Assert.AreEqual("00008", error.ResponseCode);
        Assert.AreEqual("invalid_token", error.Error);
    }

    /// <summary>
    /// 目的: Withdraw / Returns Unauthorized For Wrong Password の仕様を検証する。
    /// 入力値: 正しい主体に紐づかない誤った認証情報。
    /// 期待値: 401 Unauthorized と invalid_token 系のエラーを返すこと。
    /// </summary>
    [TestMethod]
    public void Withdraw_ReturnsUnauthorizedForWrongPassword()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("withdraw-wrong-password@example.com", "Passw0rd!", "Withdraw User", new DateOnly(2000, 1, 1));
        var stepUp = new StepUpService(users);
        StepUpGrant grant = IssueEmailStepUp(stepUp, "withdraw-wrong-password@example.com");
        var controller = EndpointTestHelper.WithHttpContext(new AccountController(users, stepUp));
        var request = new WithdrawalRequest("withdraw-wrong-password@example.com", "WrongPassw0rd!", grant.StepUpToken);

        ErrorOutput error = EndpointTestHelper.AssertError(controller.Withdraw(request), 401);

        Assert.AreEqual("00008", error.ResponseCode);
        Assert.AreEqual("invalid_token", error.Error);
    }

    /// <summary>
    /// 目的: Withdraw / Returns Unauthorized For Step Up Subject Mismatch の仕様を検証する。
    /// 入力値: Withdraw / Returns Unauthorized For Step Up Subject Mismatch を確認するためにテスト内で作成したデータ。
    /// 期待値: 401 Unauthorized と invalid_token 系のエラーを返すこと。
    /// </summary>
    [TestMethod]
    public void Withdraw_ReturnsUnauthorizedForStepUpSubjectMismatch()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("withdraw-owner@example.com", "Passw0rd!", "Withdraw User", new DateOnly(2000, 1, 1), "withdraw_owner");
        users.CreateUser("withdraw-other@example.com", "Passw0rd!", "Other User", new DateOnly(2000, 1, 1), "withdraw_other");
        var stepUp = new StepUpService(users);
        StepUpGrant grant = IssueEmailStepUp(stepUp, "withdraw-other@example.com");
        var controller = EndpointTestHelper.WithHttpContext(new AccountController(users, stepUp));
        var request = new WithdrawalRequest("withdraw-owner@example.com", "Passw0rd!", grant.StepUpToken);

        ErrorOutput error = EndpointTestHelper.AssertError(controller.Withdraw(request), 401);

        Assert.AreEqual("00008", error.ResponseCode);
        Assert.AreEqual("invalid_token", error.Error);
    }

    /// <summary>
    /// 目的: Withdraw / Returns Bad Request For Missing Password の仕様を検証する。
    /// 入力値: 必須項目または認証ヘッダーを欠落させた入力値。
    /// 期待値: 400 Bad Request 相当のエラーを返すこと。
    /// </summary>
    [TestMethod]
    public void Withdraw_ReturnsBadRequestForMissingPassword()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("withdraw-missing-password@example.com", "Passw0rd!", "Withdraw User", new DateOnly(2000, 1, 1));
        var stepUp = new StepUpService(users);
        StepUpGrant grant = IssueEmailStepUp(stepUp, "withdraw-missing-password@example.com");
        var controller = EndpointTestHelper.WithHttpContext(new AccountController(users, stepUp));
        var request = new WithdrawalRequest("withdraw-missing-password@example.com", string.Empty, grant.StepUpToken);

        ErrorOutput error = EndpointTestHelper.AssertError(controller.Withdraw(request), 400);

        Assert.AreEqual("00001", error.ResponseCode);
        Assert.AreEqual("invalid_request", error.Error);
        Assert.AreEqual("password is required", error.ErrorDescription);
    }

    private static StepUpGrant IssueEmailStepUp(StepUpService stepUp, string email)
    {
        MfaEmailChallenge challenge = stepUp.StartEmailChallenge(email);
        return stepUp.VerifyEmailChallenge(email, challenge.Code);
    }
}
