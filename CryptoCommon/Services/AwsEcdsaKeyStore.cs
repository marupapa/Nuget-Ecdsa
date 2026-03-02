using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Amazon;
using Amazon.SecretsManager;
using Amazon.SecretsManager.Model;
using CryptoCommon.Interfaces;
using CryptoCommon.Models;
using Microsoft.Extensions.Logging;

namespace CryptoCommon.Services;

/// <summary>
/// AWS Secrets Manager를 사용한 ECDSA 키 저장소
/// .NET 10: Lock 타입, IAsyncDisposable, Primary Constructor 활용
/// </summary>
public sealed class AwsEcdsaKeyStore(
    IAmazonSecretsManager secretsManager,
    ILogger<AwsEcdsaKeyStore> logger,
    AwsKeyStoreOptions options) : IEcdsaKeyStore, IAsyncDisposable
{
    // .NET 10: System.Threading.Lock (Monitor 대체, 더 안전한 lock 스코프)
    private readonly Lock _cacheLock = new();
    private EcdsaKeyPair? _cachedKeyPair;
    private DateTimeOffset _cacheExpiry = DateTimeOffset.MinValue;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        WriteIndented = false
    };

    /// <inheritdoc/>
    public async Task<EcdsaKeyPair> GetActiveKeyPairAsync(CancellationToken cancellationToken = default)
    {
        // Lock-free 캐시 read
        if (_cachedKeyPair is { } cached && DateTimeOffset.UtcNow < _cacheExpiry)
        {
            logger.LogDebug("캐시에서 ECDSA 키 반환 (KeyId: {KeyId})", cached.KeyId);
            return cached;
        }

        // .NET 10: Lock.EnterScope() - IDisposable 기반 lock 스코프
        using (_cacheLock.EnterScope())
        {
            // Double-check locking
            if (_cachedKeyPair is { } rechecked && DateTimeOffset.UtcNow < _cacheExpiry)
                return rechecked;

            var keyPair = await FetchSecretAsync(options.ActiveKeySecretName, cancellationToken);
            _cachedKeyPair = keyPair;
            _cacheExpiry = DateTimeOffset.UtcNow.Add(options.CacheTtl);

            logger.LogInformation("AWS Secrets Manager에서 ECDSA 키 로드 완료 (KeyId: {KeyId})", keyPair.KeyId);
            return keyPair;
        }
    }

    /// <inheritdoc/>
    public async Task<EcdsaKeyPair> GetKeyPairByIdAsync(string keyId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyId);
        var secretName = $"{options.KeySecretPrefix}/{keyId}";
        logger.LogDebug("키 ID로 ECDSA 키 조회: {SecretName}", secretName);
        return await FetchSecretAsync(secretName, cancellationToken);
    }

    /// <inheritdoc/>
    public async Task<EcdsaKeyPair> GenerateAndStoreKeyPairAsync(CancellationToken cancellationToken = default)
    {
        logger.LogInformation("새 ECDSA 키 페어 생성 시작");

        // .NET 10: RandomNumberGenerator.GetBytes로 암호학적 안전 ID 생성
        var keyId = Convert.ToHexString(RandomNumberGenerator.GetBytes(4));

        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var keyPair = new EcdsaKeyPair
        {
            KeyId = keyId,
            PrivateKeyPem = ExportPrivateKeyPem(ecdsa),
            PublicKeyPem = ExportPublicKeyPem(ecdsa),
            CreatedAt = DateTimeOffset.UtcNow,
            Curve = "P-256"
        };

        var secretValue = JsonSerializer.Serialize(keyPair, JsonOptions);

        // 키 이력 저장
        await StoreSecretAsync(
            $"{options.KeySecretPrefix}/{keyId}",
            secretValue,
            $"ECDSA Key Pair - {keyId}",
            cancellationToken);

        // 활성 키 갱신
        await UpdateSecretAsync(options.ActiveKeySecretName, secretValue, cancellationToken);

        // 캐시 무효화
        using (_cacheLock.EnterScope())
        {
            _cachedKeyPair = null;
            _cacheExpiry = DateTimeOffset.MinValue;
        }

        logger.LogInformation("새 ECDSA 키 생성 완료 (KeyId: {KeyId})", keyId);
        return keyPair;
    }

    /// <inheritdoc/>
    public async Task<EcdsaKeyPair> RotateKeyPairAsync(CancellationToken cancellationToken = default)
    {
        logger.LogInformation("ECDSA 키 로테이션 시작");
        return await GenerateAndStoreKeyPairAsync(cancellationToken);
    }

    // ─── Private Helpers ───────────────────────────────────────────────────────

    private async Task<EcdsaKeyPair> FetchSecretAsync(string secretName, CancellationToken ct)
    {
        try
        {
            var response = await secretsManager.GetSecretValueAsync(
                new GetSecretValueRequest { SecretId = secretName }, ct);

            var secretString = response.SecretString
                ?? throw new InvalidOperationException($"시크릿 '{secretName}'이 비어 있습니다.");

            return JsonSerializer.Deserialize<EcdsaKeyPair>(secretString, JsonOptions)
                ?? throw new InvalidOperationException($"시크릿 '{secretName}' 역직렬화 실패.");
        }
        catch (ResourceNotFoundException ex)
        {
            logger.LogError(ex, "시크릿을 찾을 수 없음: {SecretName}", secretName);
            throw new KeyNotFoundException($"ECDSA 키를 찾을 수 없습니다: {secretName}", ex);
        }
    }

    private async Task StoreSecretAsync(string name, string value, string description, CancellationToken ct)
    {
        try
        {
            // .NET 10: Collection expression [..]
            await secretsManager.CreateSecretAsync(new CreateSecretRequest
            {
                Name = name,
                SecretString = value,
                Description = description,
                Tags = [.. options.Tags.Select(t => new Tag { Key = t.Key, Value = t.Value })]
            }, ct);
        }
        catch (ResourceExistsException)
        {
            await UpdateSecretAsync(name, value, ct);
        }
    }

    private async Task UpdateSecretAsync(string name, string value, CancellationToken ct) =>
        await secretsManager.PutSecretValueAsync(
            new PutSecretValueRequest { SecretId = name, SecretString = value }, ct);

    private static string ExportPrivateKeyPem(ECDsa ecdsa)
    {
        var bytes = ecdsa.ExportECPrivateKey();
        return $"-----BEGIN EC PRIVATE KEY-----\n{Convert.ToBase64String(bytes, Base64FormattingOptions.InsertLineBreaks)}\n-----END EC PRIVATE KEY-----";
    }

    private static string ExportPublicKeyPem(ECDsa ecdsa)
    {
        var bytes = ecdsa.ExportSubjectPublicKeyInfo();
        return $"-----BEGIN PUBLIC KEY-----\n{Convert.ToBase64String(bytes, Base64FormattingOptions.InsertLineBreaks)}\n-----END PUBLIC KEY-----";
    }

    public ValueTask DisposeAsync()
    {
        GC.SuppressFinalize(this);
        return ValueTask.CompletedTask;
    }
}

/// <summary>
/// AWS Key Store 설정 옵션
/// </summary>
public sealed class AwsKeyStoreOptions
{
    /// <summary>활성 키가 저장될 시크릿 이름</summary>
    public string ActiveKeySecretName { get; set; } = "crypto/ecdsa/active-key";

    /// <summary>키 이력 저장 경로 접두사</summary>
    public string KeySecretPrefix { get; set; } = "crypto/ecdsa/keys";

    /// <summary>캐시 TTL (기본 5분)</summary>
    public TimeSpan CacheTtl { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>AWS 리전</summary>
    public string AwsRegion { get; set; } = "ap-northeast-2";

    /// <summary>시크릿에 추가할 태그</summary>
    public Dictionary<string, string> Tags { get; set; } = new()
    {
        ["Application"] = "CryptoCommon",
        ["Environment"] = "Production"
    };
}
