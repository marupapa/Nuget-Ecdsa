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
/// AWS Secrets Manager を使用した ECDSA 鍵ストア
/// 注意: Lock.EnterScope() は async メソッド内では使用不可のため、
///       キャッシュの同期制御には SemaphoreSlim(1,1) を使用します。
/// </summary>
public sealed class AwsEcdsaKeyStore(
    IAmazonSecretsManager secretsManager,
    ILogger<AwsEcdsaKeyStore> logger,
    AwsKeyStoreOptions options) : IEcdsaKeyStore, IAsyncDisposable
{
    // async メソッド内では Lock.EnterScope() を await をまたいで保持できないため
    // SemaphoreSlim(1,1) で非同期対応のミューテックスとして使用する
    private readonly SemaphoreSlim _cacheLock = new(1, 1);
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
        // ロックなしで高速パスを確認（読み取り専用）
        if (_cachedKeyPair is { } cached && DateTimeOffset.UtcNow < _cacheExpiry)
        {
            logger.LogDebug("キャッシュから ECDSA 鍵を返却 (KeyId: {KeyId})", cached.KeyId);
            return cached;
        }

        // 非同期ロック取得（await をまたいで保持可能）
        await _cacheLock.WaitAsync(cancellationToken);
        try
        {
            // ダブルチェックロッキング
            if (_cachedKeyPair is { } rechecked && DateTimeOffset.UtcNow < _cacheExpiry)
                return rechecked;

            var keyPair = await FetchSecretAsync(options.ActiveKeySecretName, cancellationToken);
            _cachedKeyPair = keyPair;
            _cacheExpiry = DateTimeOffset.UtcNow.Add(options.CacheTtl);

            logger.LogInformation("AWS Secrets Manager から ECDSA 鍵を読み込み完了 (KeyId: {KeyId})", keyPair.KeyId);
            return keyPair;
        }
        finally
        {
            _cacheLock.Release();
        }
    }

    /// <inheritdoc/>
    public async Task<EcdsaKeyPair> GetKeyPairByIdAsync(string keyId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyId);
        var secretName = $"{options.KeySecretPrefix}/{keyId}";
        logger.LogDebug("鍵IDで ECDSA 鍵を検索: {SecretName}", secretName);
        return await FetchSecretAsync(secretName, cancellationToken);
    }

    /// <inheritdoc/>
    public async Task<EcdsaKeyPair> GenerateAndStoreKeyPairAsync(CancellationToken cancellationToken = default)
    {
        logger.LogInformation("新しい ECDSA 鍵ペアの生成を開始");

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

        // 鍵の履歴を保存
        await StoreSecretAsync(
            $"{options.KeySecretPrefix}/{keyId}",
            secretValue,
            $"ECDSA Key Pair - {keyId}",
            cancellationToken);

        // アクティブ鍵を更新
        await UpdateSecretAsync(options.ActiveKeySecretName, secretValue, cancellationToken);

        // キャッシュを無効化（ロック不要: 単純な参照代入はアトミック）
        _cachedKeyPair = null;
        _cacheExpiry = DateTimeOffset.MinValue;

        logger.LogInformation("新しい ECDSA 鍵の生成が完了 (KeyId: {KeyId})", keyId);
        return keyPair;
    }

    /// <inheritdoc/>
    public async Task<EcdsaKeyPair> RotateKeyPairAsync(CancellationToken cancellationToken = default)
    {
        logger.LogInformation("ECDSA 鍵のローテーションを開始");
        return await GenerateAndStoreKeyPairAsync(cancellationToken);
    }

    // ─── プライベートヘルパー ──────────────────────────────────────────────────

    private async Task<EcdsaKeyPair> FetchSecretAsync(string secretName, CancellationToken ct)
    {
        try
        {
            var response = await secretsManager.GetSecretValueAsync(
                new GetSecretValueRequest { SecretId = secretName }, ct);

            var secretString = response.SecretString
                ?? throw new InvalidOperationException($"シークレット '{secretName}' が空です。");

            return JsonSerializer.Deserialize<EcdsaKeyPair>(secretString, JsonOptions)
                ?? throw new InvalidOperationException($"シークレット '{secretName}' のデシリアライズに失敗しました。");
        }
        catch (ResourceNotFoundException ex)
        {
            logger.LogError(ex, "シークレットが見つかりません: {SecretName}", secretName);
            throw new KeyNotFoundException($"ECDSA 鍵が見つかりません: {secretName}", ex);
        }
    }

    private async Task StoreSecretAsync(string name, string value, string description, CancellationToken ct)
    {
        try
        {
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

    public async ValueTask DisposeAsync()
    {
        _cacheLock.Dispose();
        await ValueTask.CompletedTask;
        GC.SuppressFinalize(this);
    }
}

/// <summary>
/// AWS 鍵ストアの設定オプション
/// </summary>
public sealed class AwsKeyStoreOptions
{
    /// <summary>アクティブ鍵が保存されるシークレット名</summary>
    public string ActiveKeySecretName { get; set; } = "crypto/ecdsa/active-key";

    /// <summary>鍵履歴の保存パスのプレフィックス</summary>
    public string KeySecretPrefix { get; set; } = "crypto/ecdsa/keys";

    /// <summary>キャッシュ TTL（デフォルト: 5分）</summary>
    public TimeSpan CacheTtl { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>AWS リージョン</summary>
    public string AwsRegion { get; set; } = "ap-northeast-1";

    /// <summary>シークレットに付与するタグ</summary>
    public Dictionary<string, string> Tags { get; set; } = new()
    {
        ["Application"] = "CryptoCommon",
        ["Environment"] = "Production"
    };
}
