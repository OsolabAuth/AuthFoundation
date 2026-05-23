using AuthFoundation.Common;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
namespace AuthFoundationTest;

[TestClass]
public sealed class GmailSmtpMailTests
{
    /// <summary>
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Send Mail Async を Missing Configuration 条件で実行
    /// 期待値
    /// 　Throws Invalid Operation Exception を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
    [TestMethod]
    public async Task SendMailAsync_MissingConfiguration_ThrowsInvalidOperationException()
    {
        IConfiguration config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>())
            .Build();
        var mail = new GmailSmtpMail(config, NullLogger<GmailSmtpMail>.Instance);

        InvalidOperationException ex = await Assert.ThrowsExactlyAsync<InvalidOperationException>(() =>
            mail.SendMailAsync("to@example.com", "To User", "Subject", "<p>Hello</p>"));

        StringAssert.Contains(ex.Message, "Gmail SMTP configuration is incomplete");
    }

    /// <summary>
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Send Mail Async を Invalid From Email 条件で実行
    /// 期待値
    /// 　Throws Invalid Operation Exception を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
    [TestMethod]
    public async Task SendMailAsync_InvalidFromEmail_ThrowsInvalidOperationException()
    {
        IConfiguration config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Mail:FromEmail"] = "invalid-from-email",
                ["GmailSmtp:Host"] = "smtp.gmail.com",
                ["GmailSmtp:Port"] = "587",
                ["GmailSmtp:Username"] = "user@example.com",
                ["GmailSmtp:AppPassword"] = "dummy"
            })
            .Build();
        var mail = new GmailSmtpMail(config, NullLogger<GmailSmtpMail>.Instance);

        InvalidOperationException ex = await Assert.ThrowsExactlyAsync<InvalidOperationException>(() =>
            mail.SendMailAsync("to@example.com", "To User", "Subject", "<p>Hello</p>"));

        StringAssert.Contains(ex.Message, "Mail:FromEmail is invalid.");
    }

    /// <summary>
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Send Mail Async を Invalid Recipient Email 条件で実行
    /// 期待値
    /// 　Throws Invalid Operation Exception を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
    [TestMethod]
    public async Task SendMailAsync_InvalidRecipientEmail_ThrowsInvalidOperationException()
    {
        IConfiguration config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Mail:FromEmail"] = "from@example.com",
                ["GmailSmtp:Host"] = "smtp.gmail.com",
                ["GmailSmtp:Port"] = "587",
                ["GmailSmtp:Username"] = "user@example.com",
                ["GmailSmtp:AppPassword"] = "dummy"
            })
            .Build();
        var mail = new GmailSmtpMail(config, NullLogger<GmailSmtpMail>.Instance);

        InvalidOperationException ex = await Assert.ThrowsExactlyAsync<InvalidOperationException>(() =>
            mail.SendMailAsync("invalid-recipient", string.Empty, "Subject", "<p>Hello</p>"));

        StringAssert.Contains(ex.Message, "Recipient email is invalid.");
    }

    /// <summary>
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Ctor を Fallback Smtp Keys 条件で実行
    /// 期待値
    /// 　Are Loaded を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
    [TestMethod]
    public void Ctor_FallbackSmtpKeys_AreLoaded()
    {
        IConfiguration config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Mail:FromEmail"] = "from@example.com",
                ["Smtp:Host"] = "smtp.gmail.com",
                ["Smtp:Port"] = "587",
                ["Smtp:Username"] = "user@example.com",
                ["Smtp:Password"] = "dummy"
            })
            .Build();
        var mail = new GmailSmtpMail(config, NullLogger<GmailSmtpMail>.Instance);

        string host = (string)typeof(GmailSmtpMail)
            .GetField("_smtpHost", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!
            .GetValue(mail)!;
        string username = (string)typeof(GmailSmtpMail)
            .GetField("_smtpUsername", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!
            .GetValue(mail)!;

        Assert.AreEqual("smtp.gmail.com", host);
        Assert.AreEqual("user@example.com", username);
    }

    /// <summary>
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Ctor を Empty Mail From Email 条件で実行
    /// 期待値
    /// 　Falls Back To Gmail From Email を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
    [TestMethod]
    public void Ctor_EmptyMailFromEmail_FallsBackToGmailFromEmail()
    {
        IConfiguration config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Mail:FromEmail"] = "",
                ["GmailSmtp:FromEmail"] = "gmail-from@example.com",
                ["GmailSmtp:Host"] = "smtp.gmail.com",
                ["GmailSmtp:Port"] = "587",
                ["GmailSmtp:Username"] = "user@example.com",
                ["GmailSmtp:AppPassword"] = "dummy"
            })
            .Build();
        var mail = new GmailSmtpMail(config, NullLogger<GmailSmtpMail>.Instance);

        string senderEmail = (string)typeof(GmailSmtpMail)
            .GetField("_senderEmail", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!
            .GetValue(mail)!;

        Assert.AreEqual("gmail-from@example.com", senderEmail);
    }

    /// <summary>
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Ctor を From Email With Whitespace 条件で実行
    /// 期待値
    /// 　Is Trimmed を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
    [TestMethod]
    public void Ctor_FromEmail_WithWhitespace_IsTrimmed()
    {
        IConfiguration config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Mail:FromEmail"] = "  from@example.com\r\n",
                ["GmailSmtp:Host"] = "smtp.gmail.com",
                ["GmailSmtp:Port"] = "587",
                ["GmailSmtp:Username"] = "user@example.com",
                ["GmailSmtp:AppPassword"] = "dummy"
            })
            .Build();
        var mail = new GmailSmtpMail(config, NullLogger<GmailSmtpMail>.Instance);

        string senderEmail = (string)typeof(GmailSmtpMail)
            .GetField("_senderEmail", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!
            .GetValue(mail)!;

        Assert.AreEqual("from@example.com", senderEmail);
    }
}
