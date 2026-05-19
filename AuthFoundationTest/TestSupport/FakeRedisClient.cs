using AuthFoundation.Common;
using System.Text.Json;

namespace AuthFoundationTest.TestSupport;

internal sealed class FakeRedisClient : IRedisClient
{
    private readonly Dictionary<string, string> _values = new(StringComparer.Ordinal);
    private readonly JsonSerializerOptions _jsonOptions = new(JsonSerializerDefaults.Web);

    public Task<bool> SetStringAsync(string key, string value, TimeSpan? expiry = null, int db = -1)
    {
        _values[key] = value;
        return Task.FromResult(true);
    }

    public Task<string?> GetStringAsync(string key, int db = -1)
    {
        _values.TryGetValue(key, out string? value);
        return Task.FromResult(value);
    }

    public Task<bool> DeleteAsync(string key, int db = -1)
    {
        return Task.FromResult(_values.Remove(key));
    }

    public Task<bool> ExistsAsync(string key, int db = -1)
    {
        return Task.FromResult(_values.ContainsKey(key));
    }

    public Task<bool> ExpireAsync(string key, TimeSpan expiry, int db = -1)
    {
        return Task.FromResult(_values.ContainsKey(key));
    }

    public Task<bool> SetJsonAsync<T>(string key, T value, TimeSpan? expiry = null, int db = -1)
    {
        _values[key] = JsonSerializer.Serialize(value, _jsonOptions);
        return Task.FromResult(true);
    }

    public Task<T?> GetJsonAsync<T>(string key, int db = -1)
    {
        if (!_values.TryGetValue(key, out string? value))
        {
            return Task.FromResult(default(T));
        }

        return Task.FromResult(JsonSerializer.Deserialize<T>(value, _jsonOptions));
    }
}
