using AuthFoundation.Common;
using System.Net;
using System.Net.Mail;
using System.Text;
using System.Text.Json;

/// <summary>
/// BrevoMail class.
/// </summary>
public class BrevoMail
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<BrevoMail> _logger;
    private readonly string _provider;
    private readonly string _apiKey;
    private readonly string _senderEmail;
    private readonly string _senderName;
    private readonly string _smtpHost;
    private readonly int _smtpPort;
    private readonly string _smtpUsername;
    private readonly string _smtpPassword;
    private readonly bool _smtpEnableSsl;

    /// <summary>
    /// Initializes a new instance of BrevoMail.
    /// </summary>
    public BrevoMail(HttpClient httpClient, IConfiguration config, ILogger<BrevoMail> logger)
    {
        _httpClient = httpClient;
        _logger = logger;

        _provider = (config["Mail:Provider"] ?? "BrevoApi").Trim();

        _apiKey = config["Brevo:ApiKey"] ?? string.Empty;
        _senderEmail = config["Mail:FromEmail"] ?? config["Brevo:SenderEmail"] ?? string.Empty;
        _senderName = config["Mail:FromName"] ?? config["Brevo:SenderName"] ?? "App";

        _smtpHost = config["Smtp:Host"] ?? string.Empty;
        _smtpPort = int.TryParse(config["Smtp:Port"], out int parsedPort) ? parsedPort : 587;
        _smtpUsername = config["Smtp:Username"] ?? string.Empty;
        _smtpPassword = config["Smtp:Password"] ?? string.Empty;
        _smtpEnableSsl = !bool.TryParse(config["Smtp:EnableSsl"], out bool parsedSsl) || parsedSsl;
    }

    /// <summary>
    /// Executes SendMailAsync.
    /// </summary>
    public async Task SendMailAsync(string toEmail, string toName, string subject, string html)
    {
        if (string.Equals(_provider, "Smtp", StringComparison.OrdinalIgnoreCase))
        {
            await SendBySmtpAsync(toEmail, toName, subject, html);
            return;
        }

        if (string.IsNullOrWhiteSpace(_apiKey))
        {
            throw new InvalidOperationException("Brevo ApiKey is missing.");
        }

        if (string.IsNullOrWhiteSpace(_senderEmail))
        {
            throw new InvalidOperationException("Mail sender email is missing.");
        }

        var body = new
        {
            sender = new
            {
                name = _senderName,
                email = _senderEmail
            },
            to = new[]
            {
                new { email = toEmail, name = toName }
            },
            subject = subject,
            htmlContent = html
        };

        var request = new HttpRequestMessage(HttpMethod.Post, "https://api.brevo.com/v3/smtp/email");
        request.Headers.Add("api-key", _apiKey);
        request.Content = new StringContent(
            JsonSerializer.Serialize(body),
            Encoding.UTF8,
            "application/json");

        var response = await _httpClient.SendAsync(request);
        if (response.IsSuccessStatusCode)
        {
            return;
        }

        string responseBody = await response.Content.ReadAsStringAsync();
        string summary = string.IsNullOrWhiteSpace(responseBody)
            ? "<empty>"
            : responseBody.Trim();
        if (summary.Length > 512)
        {
            summary = summary[..512];
        }

        StructuredLog.LogInfo(_logger, "BrevoMail.SendMailFailed", new
        {
            StatusCode = (int)response.StatusCode,
            response.ReasonPhrase,
            Body = summary
        });

        throw new HttpRequestException(
            $"Brevo API error: {(int)response.StatusCode} ({response.ReasonPhrase}). Body: {summary}");
    }

    private async Task SendBySmtpAsync(string toEmail, string toName, string subject, string html)
    {
        if (string.IsNullOrWhiteSpace(_smtpHost) ||
            string.IsNullOrWhiteSpace(_smtpUsername) ||
            string.IsNullOrWhiteSpace(_smtpPassword) ||
            string.IsNullOrWhiteSpace(_senderEmail))
        {
            throw new InvalidOperationException("SMTP configuration is incomplete.");
        }

        using var message = new MailMessage
        {
            From = new MailAddress(_senderEmail, _senderName),
            Subject = subject,
            Body = html,
            IsBodyHtml = true
        };
        message.To.Add(new MailAddress(toEmail, toName));

        using var client = new SmtpClient(_smtpHost, _smtpPort)
        {
            EnableSsl = _smtpEnableSsl,
            DeliveryMethod = SmtpDeliveryMethod.Network,
            UseDefaultCredentials = false,
            Credentials = new NetworkCredential(_smtpUsername, _smtpPassword),
            Timeout = 30000
        };

        await client.SendMailAsync(message);
    }
}
