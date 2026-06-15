namespace AuthFoundation.Services;

public interface IUserStore
{
    UserRecord CreateUser(
        string email,
        string password,
        string name,
        DateOnly birthDate,
        string? subject = null,
        string? acceptedTermsId = null);

    UserRecord Authenticate(string email, string password);

    UserRecord ChangePassword(string email, string currentPassword, string newPassword);

    UserRecord ResetPassword(string email, DateOnly birthDate, string newPassword);

    UserRecord Withdraw(string email, string password);

    UserRecord FindByEmail(string email);
}

public sealed record UserRecord(
    string Subject,
    string Email,
    string Name,
    DateOnly BirthDate,
    string? AcceptedTermsId,
    string PasswordHash,
    DateTimeOffset CreatedAt);
