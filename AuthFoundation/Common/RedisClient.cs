using StackExchange.Redis;
using System.Text.Json;

namespace AuthFoundation.Common
{
    /// <summary>
    /// IRedisClient interface.
    /// </summary>
    public interface IRedisClient
    {
        Task<bool> SetStringAsync(string key, string value, TimeSpan? expiry = null, int db = -1);

        Task<string?> GetStringAsync(string key, int db = -1);

        Task<bool> DeleteAsync(string key, int db = -1);

        Task<bool> ExistsAsync(string key, int db = -1);

        Task<bool> ExpireAsync(string key, TimeSpan expiry, int db = -1);

        Task<bool> SetJsonAsync<T>(string key, T value, TimeSpan? expiry = null, int db = -1);

        Task<T?> GetJsonAsync<T>(string key, int db = -1);
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
            IDatabase database = GetDatabase(db);
            return await database.StringSetAsync(key, value, expiry);
        }

        /// <summary>
        /// Executes GetStringAsync.
        /// </summary>
        public async Task<string?> GetStringAsync(string key, int db = -1)
        {
            ValidateKey(key);
            IDatabase database = GetDatabase(db);

            RedisValue value = await database.StringGetAsync(key);
            return value.HasValue ? value.ToString() : null;
        }

        /// <summary>
        /// Executes DeleteAsync.
        /// </summary>
        public async Task<bool> DeleteAsync(string key, int db = -1)
        {
            ValidateKey(key);
            IDatabase database = GetDatabase(db);
            return await database.KeyDeleteAsync(key);
        }

        /// <summary>
        /// Executes ExistsAsync.
        /// </summary>
        public async Task<bool> ExistsAsync(string key, int db = -1)
        {
            ValidateKey(key);
            IDatabase database = GetDatabase(db);
            return await database.KeyExistsAsync(key);
        }

        /// <summary>
        /// Executes ExpireAsync.
        /// </summary>
        public async Task<bool> ExpireAsync(string key, TimeSpan expiry, int db = -1)
        {
            ValidateKey(key);
            IDatabase database = GetDatabase(db);
            return await database.KeyExpireAsync(key, expiry);
        }

        public async Task<bool> SetJsonAsync<T>(string key, T value, TimeSpan? expiry = null, int db = -1)
        {
            ValidateKey(key);
            IDatabase database = GetDatabase(db);

            string json = JsonSerializer.Serialize(value, JsonOptions);
            return await database.StringSetAsync(key, json, expiry);
        }

        public async Task<T?> GetJsonAsync<T>(string key, int db = -1)
        {
            ValidateKey(key);
            IDatabase database = GetDatabase(db);

            RedisValue value = await database.StringGetAsync(key);
            if (!value.HasValue)
            {
                return default;
            }

            return JsonSerializer.Deserialize<T>(value.ToString(), JsonOptions);
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
