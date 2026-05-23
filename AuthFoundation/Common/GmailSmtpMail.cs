using System.Net;
using System.Net.Mail;

namespace AuthFoundation.Common;

/// <summary>
/// Gmail SMTP mail sender.
/// </summary>
public sealed class GmailSmtpMail
{
    private readonly ILogger<GmailSmtpMail> _logger;
    private readonly string _senderEmail;
    private readonly string _senderName;
    private readonly string _smtpHost;
    private readonly int _smtpPort;
    private readonly string _smtpUsername;
    private readonly string _smtpPassword;
    private readonly bool _smtpEnableSsl;

    /// <summary>
    /// Initializes a new instance of GmailSmtpMail.
    /// </summary>
    public GmailSmtpMail(IConfiguration config, ILogger<GmailSmtpMail> logger)
    {
        _logger = logger;

        _senderEmail = GetFirstNonEmpty(config["Mail:FromEmail"], config["GmailSmtp:FromEmail"], config["Smtp:FromEmail"]);
        _senderName = GetFirstNonEmpty(config["Mail:FromName"], config["GmailSmtp:FromName"], config["Smtp:FromName"]);
        if (string.IsNullOrWhiteSpace(_senderName))
        {
            _senderName = "AuthFoundation";
        }

        _smtpHost = GetFirstNonEmpty(config["GmailSmtp:Host"], config["Smtp:Host"]);
        if (string.IsNullOrWhiteSpace(_smtpHost))
        {
            _smtpHost = "smtp.gmail.com";
        }
        string smtpPort = GetFirstNonEmpty(config["GmailSmtp:Port"], config["Smtp:Port"]);
        _smtpPort = int.TryParse(smtpPort, out int parsedPort) ? parsedPort : 587;
        _smtpUsername = GetFirstNonEmpty(config["GmailSmtp:Username"], config["Smtp:Username"]);
        _smtpPassword = GetFirstNonEmpty(config["GmailSmtp:AppPassword"], config["GmailSmtp:Password"], config["Smtp:Password"]);
        string smtpEnableSsl = GetFirstNonEmpty(config["GmailSmtp:EnableSsl"], config["Smtp:EnableSsl"]);
        _smtpEnableSsl = !bool.TryParse(smtpEnableSsl, out bool parsedSsl) || parsedSsl;
    }

    private static string GetFirstNonEmpty(params string?[] values)
    {
        foreach (string? value in values)
        {
            if (!string.IsNullOrWhiteSpace(value))
            {
                return value.Trim();
            }
        }

        return string.Empty;
    }

    /// <summary>
    /// Sends email by Gmail SMTP.
    /// </summary>
    public async Task SendMailAsync(string toEmail, string toName, string subject, string html)
    {
        string normalizedToEmail = toEmail.Trim();
        string normalizedToName = toName.Trim();

        if (string.IsNullOrWhiteSpace(_smtpHost) ||
            string.IsNullOrWhiteSpace(_smtpUsername) ||
            string.IsNullOrWhiteSpace(_smtpPassword) ||
            string.IsNullOrWhiteSpace(_senderEmail))
        {
            throw new InvalidOperationException("Gmail SMTP configuration is incomplete.");
        }

        if (!IsValidMailAddress(_senderEmail))
        {
            throw new InvalidOperationException("Mail:FromEmail is invalid.");
        }

        if (!IsValidMailAddress(normalizedToEmail))
        {
            throw new InvalidOperationException("Recipient email is invalid.");
        }

        using var message = new MailMessage
        {
            From = new MailAddress(_senderEmail, _senderName),
            Subject = subject,
            Body = html,
            IsBodyHtml = true
        };
        message.To.Add(new MailAddress(normalizedToEmail, normalizedToName));

        using var client = new SmtpClient(_smtpHost, _smtpPort)
        {
            EnableSsl = _smtpEnableSsl,
            DeliveryMethod = SmtpDeliveryMethod.Network,
            UseDefaultCredentials = false,
            Credentials = new NetworkCredential(_smtpUsername, _smtpPassword),
            Timeout = 30000
        };

        try
        {
            await client.SendMailAsync(message);
        }
        catch (Exception ex)
        {
            StructuredLog.LogException(_logger, "GmailSmtpMail.SendMailFailed", ex);
            throw;
        }
    }

    private static bool IsValidMailAddress(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        return MailAddress.TryCreate(value, out MailAddress? parsed)
            && string.Equals(parsed.Address, value, StringComparison.OrdinalIgnoreCase);
    }
}

