namespace AuthFoundation.Session;

public sealed class EmailSendCooldownSession
{
    public const string Value = "1";

    public static string GetRedisKey(string purpose, string email)
    {
        return $"auth:session:email_send_cooldown:{purpose}:{email.ToLowerInvariant()}";
    }
}
