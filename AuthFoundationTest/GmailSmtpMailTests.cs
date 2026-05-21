using AuthFoundation.Common;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
namespace AuthFoundationTest;

[TestClass]
public sealed class GmailSmtpMailTests
{
    /// <summary>
    /// 検証項目: Gmail SMTP設定不足時にネットワーク送信せずInvalidOperationExceptionを送出すること。
    /// </summary>
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
    /// 検証項目: 旧Smtp設定キーのみでもSMTP設定として読み込めること。
    /// </summary>
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
    /// 検証項目: Mail:FromEmail が空文字でも GmailSmtp:FromEmail を採用すること。
    /// </summary>
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
}
