using System.Security.Cryptography;
using AuthFoundation.Common;

namespace AuthFoundation.Services;

public sealed class SigningKeyProvider : IDisposable
{
    private readonly RSA _rsa;
    private readonly object _sync = new();

    private SigningKeyProvider(string keyId, RSA rsa)
    {
        KeyId = keyId;
        _rsa = rsa;
    }

    public string KeyId { get; }

    public static SigningKeyProvider FromConfig()
    {
        return FromPem(AppConfig.SigningKeyId, AppConfig.SigningKeyPrivateKeyPem);
    }

    public static SigningKeyProvider FromPem(string keyId, string privateKeyPem)
    {
        if (string.IsNullOrWhiteSpace(keyId) || string.IsNullOrWhiteSpace(privateKeyPem))
        {
            throw new ApiException(
                Code.INTERNAL_SERVER_ERROR.InternalCode,
                Code.INTERNAL_SERVER_ERROR.StatusCode,
                Code.INTERNAL_SERVER_ERROR.Error,
                "signing key is not configured");
        }

        RSA rsa = RSA.Create();
        try
        {
            rsa.ImportFromPem(privateKeyPem.Replace("\\n", "\n", StringComparison.Ordinal));
            return new SigningKeyProvider(keyId, rsa);
        }
        catch (Exception ex) when (ex is ArgumentException or CryptographicException)
        {
            rsa.Dispose();
            throw new ApiException(
                Code.INTERNAL_SERVER_ERROR.InternalCode,
                Code.INTERNAL_SERVER_ERROR.StatusCode,
                Code.INTERNAL_SERVER_ERROR.Error,
                "signing key is invalid");
        }
    }

    public RSAParameters ExportPublicParameters()
    {
        lock (_sync)
        {
            return _rsa.ExportParameters(false);
        }
    }

    public byte[] SignData(byte[] data)
    {
        lock (_sync)
        {
            return _rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
    }

    public void Dispose()
    {
        _rsa.Dispose();
    }
}
