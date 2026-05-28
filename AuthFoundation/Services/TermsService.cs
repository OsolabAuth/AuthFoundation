namespace AuthFoundation.Services;

public sealed class TermsService
{
    public const string CurrentTermsId = "osolab-auth-terms-v1";
    public const string CurrentVersion = "2026-05-28";

    public TermsDocument Current()
    {
        return new TermsDocument(
            CurrentTermsId,
            CurrentVersion,
            "OsolabAuth Terms",
            "Use OsolabAuth only for your own account and authorized clients. Keep credentials secret. OsolabAuth may record authentication and consent events for security and audit purposes.");
    }
}

public sealed record TermsDocument(
    string TermsId,
    string Version,
    string Title,
    string Body);
