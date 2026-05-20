using AuthFoundation.Session;
using StackExchange.Redis;
using System.Text.Json;

namespace AuthFoundation.Common
{
    /// <summary>
    /// IRedisClient interface.
    /// </summary>
    public interface IRedisClient
    {
        Task<bool> SetStringAsync(string key, string value, TimeSpan? expiry , int db);

        Task<string?> GetStringAsync(string key, int db);

        Task<bool> DeleteAsync(string key, int db);

        Task<bool> ExistsAsync(string key, int db);

        Task<bool> ExpireAsync(string key, TimeSpan expiry, int db);

        Task<bool> SetJsonAsync<T>(string key, T value, TimeSpan? expiry, int db);

        Task<T?> GetJsonAsync<T>(string key, int db);
    }

    /// <summary>
    /// RedisClient class.
    /// </summary>
    public class RedisClient : IRedisClient
    {
        private readonly IConnectionMultiplexer _connectionMultiplexer;
        private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

        /// <summary>
        /// Initializes a new instance of RedisClient.
        /// </summary>
        public RedisClient(IConnectionMultiplexer connectionMultiplexer)
        {
            _connectionMultiplexer = connectionMultiplexer;
        }

        /// <summary>
        /// Executes SetStringAsync.
        /// </summary>
        public async Task<bool> SetStringAsync(string key, string value, TimeSpan? expiry = null, int db = -1)
        {
            ValidateKey(key);
            IDatabase database = GetDatabaseForKey(key, db);
            return await database.StringSetAsync(key, value, expiry);
        }

        /// <summary>
        /// Executes GetStringAsync.
        /// </summary>
        public async Task<string?> GetStringAsync(string key, int db = -1)
        {
            ValidateKey(key);
            IDatabase database = GetDatabaseForKey(key, db);

            RedisValue value = await database.StringGetAsync(key);
            return value.HasValue ? value.ToString() : null;
        }

        /// <summary>
        /// Executes DeleteAsync.
        /// </summary>
        public async Task<bool> DeleteAsync(string key, int db = -1)
        {
            ValidateKey(key);
            IDatabase database = GetDatabaseForKey(key, db);
            return await database.KeyDeleteAsync(key);
        }

        /// <summary>
        /// Executes ExistsAsync.
        /// </summary>
        public async Task<bool> ExistsAsync(string key, int db = -1)
        {
            ValidateKey(key);
            IDatabase database = GetDatabaseForKey(key, db);
            return await database.KeyExistsAsync(key);
        }

        /// <summary>
        /// Executes ExpireAsync.
        /// </summary>
        public async Task<bool> ExpireAsync(string key, TimeSpan expiry, int db = -1)
        {
            ValidateKey(key);
            IDatabase database = GetDatabaseForKey(key, db);
            return await database.KeyExpireAsync(key, expiry);
        }

        public async Task<bool> SetJsonAsync<T>(string key, T value, TimeSpan? expiry = null, int db = -1)
        {
            ValidateKey(key);
            IDatabase database = GetDatabaseForKey(key, db);

            string json = JsonSerializer.Serialize(value, JsonOptions);
            return await database.StringSetAsync(key, json, expiry);
        }

        public async Task<T?> GetJsonAsync<T>(string key, int db = -1)
        {
            ValidateKey(key);
            IDatabase database = GetDatabaseForKey(key, db);

            RedisValue value = await database.StringGetAsync(key);
            if (!value.HasValue)
            {
                return default;
            }

            return JsonSerializer.Deserialize<T>(value.ToString(), JsonOptions);
        }

        /// <summary>
        /// Executes GetDatabaseForKey.
        /// </summary>
        private IDatabase GetDatabaseForKey(string key, int db)
        {
            if (db >= 0)
            {
                return GetDatabase(db);
            }

            int resolvedDb = ResolveDbByKey(key);
            return GetDatabase(resolvedDb);
        }

        /// <summary>
        /// Executes ResolveDbByKey.
        /// </summary>
        private static int ResolveDbByKey(string key)
        {
            if (key.StartsWith(AuthSession.RedisKeyPrefix, StringComparison.Ordinal))
            {
                return AppConfig.RedisDbLoginSession;
            }

            if (key.StartsWith(Code.AuthCode.REDIS_KEY_PREFIX, StringComparison.Ordinal))
            {
                return AppConfig.RedisDbAuthCode;
            }

            if (key.StartsWith(Code.AccessToken.REDIS_KEY_PREFIX, StringComparison.Ordinal))
            {
                return AppConfig.RedisDbAccessToken;
            }

            if (key.StartsWith(Code.RefreshToken.REDIS_KEY_PREFIX, StringComparison.Ordinal))
            {
                return AppConfig.RedisDbRefreshToken;
            }

            if (key.StartsWith(AuthorizationSession.RedisKeyPrefix, StringComparison.Ordinal))
            {
                return AppConfig.RedisDbAuthorizationSession;
            }

            if (key.StartsWith(MailVerificationSession.RedisKeyPrefix, StringComparison.Ordinal))
            {
                return AppConfig.RedisDbMailVerification;
            }

            if (key.StartsWith(Code.Revocation.ID_TOKEN_PREFIX, StringComparison.Ordinal))
            {
                return AppConfig.RedisDbIdTokenRevocation;
            }

            if (key.StartsWith(Code.Revocation.LOGOUT_ALL_PREFIX, StringComparison.Ordinal))
            {
                return AppConfig.RedisDbLogoutAllRevocation;
            }

            return AppConfig.RedisDbDefault;
        }

        /// <summary>
        /// Executes GetDatabase.
        /// </summary>
        private IDatabase GetDatabase(int db)
        {
            return _connectionMultiplexer.GetDatabase(db);
        }

        /// <summary>
        /// Executes ValidateKey.
        /// </summary>
        private static void ValidateKey(string key)
        {
            if (string.IsNullOrWhiteSpace(key))
            {
                throw new ArgumentException("Redis key must not be empty.", nameof(key));
            }
        }
    }
}
