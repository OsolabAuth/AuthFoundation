using AuthFoundation.Common;
using AuthFoundation.Data;
using AuthFoundation.Data.Scaffolded;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;

namespace AuthFoundation.Services;

public sealed class SqlUserStore : IUserStore
{
    private const string PasswordNonce = "ARGON2ID";
    private readonly IDbContextFactory<OsolabAuthContext> _contextFactory;

    public SqlUserStore(IDbContextFactory<OsolabAuthContext> contextFactory)
    {
        _contextFactory = contextFactory;
    }

    public UserRecord CreateUser(
        string email,
        string password,
        string name,
        DateOnly birthDate,
        string? subject = null,
        string? acceptedTermsId = null)
    {
        string normalizedEmail = email.Trim();
        string userSubject = NormalizeSubject(subject);
        string passwordHash = PasswordUtil.Hash(password);
        DateTime now = DateTime.UtcNow;

        using OsolabAuthContext db = _contextFactory.CreateDbContext();
        using var transaction = db.Database.BeginTransaction();
        try
        {
            if (FindActiveUserByEmail(db, normalizedEmail) is not null)
            {
                throw DuplicateEmail();
            }

            db.OsolabUsers.Add(new OsolabUser
            {
                OsolabId = userSubject,
                Email = normalizedEmail,
                Password = passwordHash,
                Nonce = PasswordNonce,
                CreateDatetime = now,
                UpdateDatetime = now,
                Status = 1
            });

            UpsertUserInfo(db, userSubject, normalizedEmail, name, birthDate, now);
            if (!string.IsNullOrWhiteSpace(acceptedTermsId))
            {
                UpsertCurrentTerms(db, now);
                InsertTermConsent(db, userSubject, acceptedTermsId, now);
            }

            db.SaveChanges();
            transaction.Commit();
            return new UserRecord(userSubject, normalizedEmail, name, birthDate, acceptedTermsId, passwordHash, new DateTimeOffset(now, TimeSpan.Zero));
        }
        catch (ApiException)
        {
            transaction.Rollback();
            throw;
        }
        catch (DbUpdateException ex) when (IsUniqueConstraintViolation(ex))
        {
            transaction.Rollback();
            throw DuplicateEmail();
        }
    }

    public UserRecord Authenticate(string email, string password)
    {
        UserRecord user = FindByEmail(email);
        if (!PasswordUtil.Verify(password, user.PasswordHash))
        {
            throw Code.UNAUTHORIZED;
        }

        return PasswordUtil.NeedsRehash(user.PasswordHash)
            ? UpdatePasswordHash(user, PasswordUtil.Hash(password))
            : user;
    }

    public UserRecord ChangePassword(string email, string currentPassword, string newPassword)
    {
        UserRecord user = Authenticate(email, currentPassword);
        return UpdatePasswordHash(user, PasswordUtil.Hash(newPassword));
    }

    public UserRecord ResetPassword(string email, DateOnly birthDate, string newPassword)
    {
        UserRecord user = FindByEmail(email);
        if (user.BirthDate != birthDate)
        {
            throw Code.UNAUTHORIZED;
        }

        return UpdatePasswordHash(user, PasswordUtil.Hash(newPassword));
    }

    public UserRecord Withdraw(string email, string password)
    {
        UserRecord user = Authenticate(email, password);
        using OsolabAuthContext db = _contextFactory.CreateDbContext();
        OsolabUser entity = FindActiveUserByEmail(db, email.Trim()) ?? throw Code.UNAUTHORIZED;
        entity.Status = 0;
        entity.UpdateDatetime = DateTime.UtcNow;
        db.SaveChanges();
        return user;
    }

    public UserRecord FindByEmail(string email)
    {
        using OsolabAuthContext db = _contextFactory.CreateDbContext();
        OsolabUser entity = FindActiveUserByEmail(db, email.Trim()) ?? throw Code.UNAUTHORIZED;
        return ToUserRecord(db, entity);
    }

    private UserRecord UpdatePasswordHash(UserRecord user, string passwordHash)
    {
        using OsolabAuthContext db = _contextFactory.CreateDbContext();
        OsolabUser entity = db.OsolabUsers.Single(item => item.OsolabId == user.Subject && item.Status == 1);
        entity.Password = passwordHash;
        entity.Nonce = PasswordNonce;
        entity.UpdateDatetime = DateTime.UtcNow;
        db.SaveChanges();
        return user with { PasswordHash = passwordHash };
    }

    private static OsolabUser? FindActiveUserByEmail(OsolabAuthContext db, string email)
    {
        return db.OsolabUsers
            .Where(user => user.Email == email && user.Status == 1)
            .OrderByDescending(user => user.CreateDatetime)
            .FirstOrDefault();
    }

    private static UserRecord ToUserRecord(OsolabAuthContext db, OsolabUser user)
    {
        Dictionary<string, string> info = db.UserInfos
            .Where(item =>
                item.OsolabId == user.OsolabId
                && item.ClientId == AppConfig.SharedUserInfoClientId
                && item.Status == 1)
            .ToDictionary(item => item.DataKey, item => item.DataValue, StringComparer.OrdinalIgnoreCase);

        string? acceptedTermsId = db.UserTermConsents
            .Where(consent =>
                consent.OsolabId == user.OsolabId
                && consent.ClientId == AppConfig.SharedUserInfoClientId
                && consent.ConsentResult)
            .OrderByDescending(consent => consent.ConsentedDatetime)
            .Select(consent => consent.TermId)
            .FirstOrDefault();

        DateOnly birthDate = DateOnly.MinValue;
        if (info.TryGetValue("birth_date", out string? birthDateValue)
            || info.TryGetValue("birthdate", out birthDateValue))
        {
            _ = DateOnly.TryParseExact(birthDateValue, "yyyy-MM-dd", out birthDate);
        }

        return new UserRecord(
            user.OsolabId,
            user.Email,
            info.GetValueOrDefault("name") ?? user.Email,
            birthDate,
            acceptedTermsId,
            user.Password,
            new DateTimeOffset(DateTime.SpecifyKind(user.CreateDatetime, DateTimeKind.Utc)));
    }

    private static void UpsertUserInfo(
        OsolabAuthContext db,
        string subject,
        string email,
        string name,
        DateOnly birthDate,
        DateTime now)
    {
        UpsertUserInfoValue(db, subject, "sub", subject, now);
        UpsertUserInfoValue(db, subject, "email", email, now);
        UpsertUserInfoValue(db, subject, "name", name, now);
        UpsertUserInfoValue(db, subject, "preferred_username", name, now);
        UpsertUserInfoValue(db, subject, "birth_date", birthDate.ToString("yyyy-MM-dd"), now);
        UpsertUserInfoValue(db, subject, "email_verified", "true", now);
    }

    private static void UpsertUserInfoValue(
        OsolabAuthContext db,
        string subject,
        string dataKey,
        string dataValue,
        DateTime now)
    {
        UserInfo? info = db.UserInfos.Find(subject, AppConfig.SharedUserInfoClientId, dataKey);
        if (info is null)
        {
            db.UserInfos.Add(new UserInfo
            {
                OsolabId = subject,
                ClientId = AppConfig.SharedUserInfoClientId,
                DataKey = dataKey,
                DataValue = dataValue,
                CreateDatetime = now,
                UpdateDatetime = now,
                Status = 1
            });
            return;
        }

        info.DataValue = dataValue;
        info.UpdateDatetime = now;
        info.Status = 1;
    }

    private static void UpsertCurrentTerms(OsolabAuthContext db, DateTime now)
    {
        TermsDocument terms = new TermsService().Current();
        if (db.TermMasters.Find(terms.TermsId) is null)
        {
            db.TermMasters.Add(new TermMaster
            {
                TermId = terms.TermsId,
                TermType = "terms",
                Title = terms.Title,
                Version = terms.Version,
                Content = terms.Body,
                EffectiveStartDatetime = now,
                CreateDatetime = now,
                UpdateDatetime = now,
                Status = 1
            });
        }

        if (db.ClientTerms.Find(AppConfig.SharedUserInfoClientId, terms.TermsId) is null)
        {
            db.ClientTerms.Add(new ClientTerm
            {
                ClientId = AppConfig.SharedUserInfoClientId,
                TermId = terms.TermsId,
                Required = true,
                DisplayOrder = 1,
                CreateDatetime = now,
                UpdateDatetime = now,
                Status = 1
            });
        }
    }

    private static void InsertTermConsent(OsolabAuthContext db, string subject, string acceptedTermsId, DateTime now)
    {
        TermMaster term = db.TermMasters.Find(acceptedTermsId)
            ?? throw Code.REQUEST_PARAMETER_ERROR;

        db.UserTermConsents.Add(new UserTermConsent
        {
            OsolabId = subject,
            ClientId = AppConfig.SharedUserInfoClientId,
            TermId = acceptedTermsId,
            TermVersion = term.Version,
            ConsentResult = true,
            ConsentedDatetime = now,
            CreateDatetime = now
        });
    }

    private static string NormalizeSubject(string? subject)
    {
        if (!string.IsNullOrWhiteSpace(subject))
        {
            return subject.Length <= 16 ? subject : subject[..16];
        }

        return Helper.GenerateHex(16).ToUpperInvariant();
    }

    private static bool IsUniqueConstraintViolation(DbUpdateException ex)
    {
        return ex.InnerException is SqlException sql && sql.Number is 2601 or 2627;
    }

    private static ApiException DuplicateEmail()
    {
        return new ApiException(
            Code.REQUEST_PARAMETER_ERROR.InternalCode,
            Code.REQUEST_PARAMETER_ERROR.StatusCode,
            "invalid_request",
            "email is already registered");
    }
}
