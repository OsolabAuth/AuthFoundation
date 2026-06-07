using AuthFoundation.Common;
using Microsoft.Data.SqlClient;

namespace AuthFoundation.Services;

public sealed class SqlUserStore : IUserStore
{
    private const string PasswordNonce = "PBKDF2";
    private readonly string _connectionString;

    public SqlUserStore(string connectionString)
    {
        _connectionString = connectionString;
    }

    /// <summary>
    /// SQL Server上にユーザー本体、共通UserInfo、規約同意を作成する。
    /// </summary>
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
        DateTimeOffset now = DateTimeOffset.UtcNow;

        using var connection = OpenConnection();
        using SqlTransaction transaction = connection.BeginTransaction();
        try
        {
            if (FindByEmail(connection, transaction, normalizedEmail) is not null)
            {
                throw DuplicateEmail();
            }

            using (SqlCommand command = CreateCommand(
                connection,
                transaction,
                """
                INSERT INTO [auth].[osolab_user]
                    ([osolab_id], [email], [password], [nonce], [create_datetime], [update_datetime], [status])
                VALUES
                    (@osolab_id, @email, @password, @nonce, SYSUTCDATETIME(), SYSUTCDATETIME(), 1);
                """))
            {
                command.Parameters.AddWithValue("@osolab_id", userSubject);
                command.Parameters.AddWithValue("@email", normalizedEmail);
                command.Parameters.AddWithValue("@password", passwordHash);
                command.Parameters.AddWithValue("@nonce", PasswordNonce);
                command.ExecuteNonQuery();
            }

            UpsertUserInfo(connection, transaction, userSubject, normalizedEmail, name, birthDate);
            if (!string.IsNullOrWhiteSpace(acceptedTermsId))
            {
                UpsertCurrentTerms(connection, transaction);
                InsertTermConsent(connection, transaction, userSubject, acceptedTermsId);
            }

            transaction.Commit();
            return new UserRecord(userSubject, normalizedEmail, name, birthDate, acceptedTermsId, passwordHash, now);
        }
        catch (ApiException)
        {
            transaction.Rollback();
            throw;
        }
        catch (SqlException ex) when (IsUniqueConstraintViolation(ex))
        {
            transaction.Rollback();
            throw DuplicateEmail();
        }
        catch
        {
            transaction.Rollback();
            throw;
        }
    }

    /// <summary>
    /// SQL Server上のユーザーをメールアドレスとパスワードで認証する。
    /// </summary>
    public UserRecord Authenticate(string email, string password)
    {
        UserRecord user = FindByEmail(email);
        if (!PasswordUtil.Verify(password, user.PasswordHash))
        {
            throw Code.UNAUTHORIZED;
        }

        return user;
    }

    /// <summary>
    /// SQL Server上のユーザーのパスワードを変更する。
    /// </summary>
    public UserRecord ChangePassword(string email, string currentPassword, string newPassword)
    {
        UserRecord user = Authenticate(email, currentPassword);
        string passwordHash = PasswordUtil.Hash(newPassword);

        using var connection = OpenConnection();
        using SqlCommand command = CreateCommand(
            connection,
            null,
            """
            UPDATE [auth].[osolab_user]
               SET [password] = @password,
                   [nonce] = @nonce,
                   [update_datetime] = SYSUTCDATETIME()
             WHERE [osolab_id] = @osolab_id
               AND [status] = 1;
            """);
        command.Parameters.AddWithValue("@password", passwordHash);
        command.Parameters.AddWithValue("@nonce", PasswordNonce);
        command.Parameters.AddWithValue("@osolab_id", user.Subject);
        command.ExecuteNonQuery();

        return user with { PasswordHash = passwordHash };
    }

    /// <summary>
    /// SQL Server上のユーザーの生年月日を確認してパスワードを再設定する。
    /// </summary>
    public UserRecord ResetPassword(string email, DateOnly birthDate, string newPassword)
    {
        UserRecord user = FindByEmail(email);
        if (user.BirthDate != birthDate)
        {
            throw Code.UNAUTHORIZED;
        }

        string passwordHash = PasswordUtil.Hash(newPassword);
        using var connection = OpenConnection();
        using SqlCommand command = CreateCommand(
            connection,
            null,
            """
            UPDATE [auth].[osolab_user]
               SET [password] = @password,
                   [nonce] = @nonce,
                   [update_datetime] = SYSUTCDATETIME()
             WHERE [osolab_id] = @osolab_id
               AND [status] = 1;
            """);
        command.Parameters.AddWithValue("@password", passwordHash);
        command.Parameters.AddWithValue("@nonce", PasswordNonce);
        command.Parameters.AddWithValue("@osolab_id", user.Subject);
        command.ExecuteNonQuery();

        return user with { PasswordHash = passwordHash };
    }

    /// <summary>
    /// SQL Server上のユーザーを論理退会状態にする。
    /// </summary>
    public UserRecord Withdraw(string email, string password)
    {
        UserRecord user = Authenticate(email, password);
        using var connection = OpenConnection();
        using SqlCommand command = CreateCommand(
            connection,
            null,
            """
            UPDATE [auth].[osolab_user]
               SET [status] = 0,
                   [update_datetime] = SYSUTCDATETIME()
             WHERE [osolab_id] = @osolab_id
               AND [status] = 1;
            """);
        command.Parameters.AddWithValue("@osolab_id", user.Subject);
        command.ExecuteNonQuery();
        return user;
    }

    /// <summary>
    /// SQL Server上のユーザーをメールアドレスで取得する。
    /// </summary>
    public UserRecord FindByEmail(string email)
    {
        using var connection = OpenConnection();
        DbUserRecord? user = FindByEmail(connection, null, email.Trim());
        if (user is null)
        {
            throw Code.UNAUTHORIZED;
        }

        return ToUserRecord(user);
    }

    private SqlConnection OpenConnection()
    {
        var connection = new SqlConnection(_connectionString);
        connection.Open();
        return connection;
    }

    private static DbUserRecord? FindByEmail(SqlConnection connection, SqlTransaction? transaction, string email)
    {
        using SqlCommand command = CreateCommand(
            connection,
            transaction,
            """
            SELECT TOP (1)
                   u.[osolab_id],
                   u.[email],
                   u.[password],
                   u.[create_datetime],
                   MAX(CASE WHEN ui.[data_key] = 'name' THEN ui.[data_value] END) AS [name],
                   MAX(CASE WHEN ui.[data_key] = 'birth_date' THEN ui.[data_value] END) AS [birth_date],
                   MAX(CASE WHEN utc.[consent_result] = 1 THEN utc.[term_id] END) AS [accepted_terms_id]
              FROM [auth].[osolab_user] u
              LEFT JOIN [auth].[user_info] ui
                ON ui.[osolab_id] = u.[osolab_id]
               AND ui.[client_id] = @shared_client_id
               AND ui.[status] = 1
              LEFT JOIN [auth].[user_term_consent] utc
                ON utc.[osolab_id] = u.[osolab_id]
               AND utc.[client_id] = @shared_client_id
             WHERE u.[email] = @email
               AND u.[status] = 1
             GROUP BY u.[osolab_id], u.[email], u.[password], u.[create_datetime]
             ORDER BY u.[create_datetime] DESC;
            """);
        command.Parameters.AddWithValue("@shared_client_id", AppConfig.SharedUserInfoClientId);
        command.Parameters.AddWithValue("@email", email);

        using SqlDataReader reader = command.ExecuteReader();
        if (!reader.Read())
        {
            return null;
        }

        return new DbUserRecord(
            reader.GetString(0),
            reader.GetString(1),
            reader.GetString(2),
            reader.GetDateTime(3),
            ReadNullableString(reader, 4),
            ReadNullableString(reader, 5),
            ReadNullableString(reader, 6));
    }

    private static void UpsertUserInfo(
        SqlConnection connection,
        SqlTransaction transaction,
        string subject,
        string email,
        string name,
        DateOnly birthDate)
    {
        UpsertUserInfoValue(connection, transaction, subject, "sub", subject);
        UpsertUserInfoValue(connection, transaction, subject, "email", email);
        UpsertUserInfoValue(connection, transaction, subject, "name", name);
        UpsertUserInfoValue(connection, transaction, subject, "preferred_username", name);
        UpsertUserInfoValue(connection, transaction, subject, "birth_date", birthDate.ToString("yyyy-MM-dd"));
        UpsertUserInfoValue(connection, transaction, subject, "email_verified", "true");
    }

    private static void UpsertUserInfoValue(
        SqlConnection connection,
        SqlTransaction transaction,
        string subject,
        string dataKey,
        string dataValue)
    {
        using SqlCommand command = CreateCommand(
            connection,
            transaction,
            """
            IF EXISTS (
                SELECT 1
                  FROM [auth].[user_info]
                 WHERE [osolab_id] = @osolab_id
                   AND [client_id] = @client_id
                   AND [data_key] = @data_key
            )
            BEGIN
                UPDATE [auth].[user_info]
                   SET [data_value] = @data_value,
                       [update_datetime] = SYSUTCDATETIME(),
                       [status] = 1
                 WHERE [osolab_id] = @osolab_id
                   AND [client_id] = @client_id
                   AND [data_key] = @data_key;
            END
            ELSE
            BEGIN
                INSERT INTO [auth].[user_info]
                    ([osolab_id], [client_id], [data_key], [data_value], [create_datetime], [update_datetime], [status])
                VALUES
                    (@osolab_id, @client_id, @data_key, @data_value, SYSUTCDATETIME(), SYSUTCDATETIME(), 1);
            END
            """);
        command.Parameters.AddWithValue("@osolab_id", subject);
        command.Parameters.AddWithValue("@client_id", AppConfig.SharedUserInfoClientId);
        command.Parameters.AddWithValue("@data_key", dataKey);
        command.Parameters.AddWithValue("@data_value", dataValue);
        command.ExecuteNonQuery();
    }

    private static void UpsertCurrentTerms(SqlConnection connection, SqlTransaction transaction)
    {
        TermsDocument terms = new TermsService().Current();
        using SqlCommand command = CreateCommand(
            connection,
            transaction,
            """
            IF NOT EXISTS (SELECT 1 FROM [auth].[term_master] WHERE [term_id] = @term_id)
            BEGIN
                INSERT INTO [auth].[term_master]
                    ([term_id], [term_type], [title], [version], [content], [effective_start_datetime], [effective_end_datetime], [create_datetime], [update_datetime], [status])
                VALUES
                    (@term_id, 'terms', @title, @version, @content, SYSUTCDATETIME(), NULL, SYSUTCDATETIME(), SYSUTCDATETIME(), 1);
            END;

            IF NOT EXISTS (
                SELECT 1
                  FROM [auth].[client_term]
                 WHERE [client_id] = @client_id
                   AND [term_id] = @term_id
                   AND [status] = 1
            )
            BEGIN
                INSERT INTO [auth].[client_term]
                    ([client_id], [term_id], [required], [display_order], [create_datetime], [update_datetime], [status])
                VALUES
                    (@client_id, @term_id, 1, 1, SYSUTCDATETIME(), SYSUTCDATETIME(), 1);
            END;
            """);
        command.Parameters.AddWithValue("@term_id", terms.TermsId);
        command.Parameters.AddWithValue("@client_id", AppConfig.SharedUserInfoClientId);
        command.Parameters.AddWithValue("@title", terms.Title);
        command.Parameters.AddWithValue("@version", terms.Version);
        command.Parameters.AddWithValue("@content", terms.Body);
        command.ExecuteNonQuery();
    }

    private static void InsertTermConsent(
        SqlConnection connection,
        SqlTransaction transaction,
        string subject,
        string acceptedTermsId)
    {
        using SqlCommand command = CreateCommand(
            connection,
            transaction,
            """
            INSERT INTO [auth].[user_term_consent]
                ([osolab_id], [client_id], [term_id], [term_version], [consent_result], [consented_datetime], [create_datetime])
            SELECT @osolab_id, @client_id, [term_id], [version], 1, SYSUTCDATETIME(), SYSUTCDATETIME()
              FROM [auth].[term_master]
             WHERE [term_id] = @term_id;
            """);
        command.Parameters.AddWithValue("@osolab_id", subject);
        command.Parameters.AddWithValue("@client_id", AppConfig.SharedUserInfoClientId);
        command.Parameters.AddWithValue("@term_id", acceptedTermsId);
        command.ExecuteNonQuery();
    }

    private static SqlCommand CreateCommand(SqlConnection connection, SqlTransaction? transaction, string commandText)
    {
        var command = new SqlCommand(commandText, connection, transaction);
        return command;
    }

    private static UserRecord ToUserRecord(DbUserRecord user)
    {
        DateOnly birthDate = DateOnly.MinValue;
        if (!string.IsNullOrWhiteSpace(user.BirthDate))
        {
            _ = DateOnly.TryParseExact(user.BirthDate, "yyyy-MM-dd", out birthDate);
        }

        return new UserRecord(
            user.Subject,
            user.Email,
            user.Name ?? user.Email,
            birthDate,
            user.AcceptedTermsId,
            user.PasswordHash,
            new DateTimeOffset(DateTime.SpecifyKind(user.CreatedAt, DateTimeKind.Utc)));
    }

    private static string NormalizeSubject(string? subject)
    {
        if (!string.IsNullOrWhiteSpace(subject))
        {
            return subject.Length <= 16 ? subject : subject[..16];
        }

        return Helper.GenerateHex(16).ToUpperInvariant();
    }

    private static string? ReadNullableString(SqlDataReader reader, int ordinal)
    {
        return reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);
    }

    private static bool IsUniqueConstraintViolation(SqlException ex)
    {
        return ex.Number is 2601 or 2627;
    }

    private static ApiException DuplicateEmail()
    {
        return new ApiException(
            Code.REQUEST_PARAMETER_ERROR.InternalCode,
            Code.REQUEST_PARAMETER_ERROR.StatusCode,
            "invalid_request",
            "email is already registered");
    }

    private sealed record DbUserRecord(
        string Subject,
        string Email,
        string PasswordHash,
        DateTime CreatedAt,
        string? Name,
        string? BirthDate,
        string? AcceptedTermsId);
}
