using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Amazon.SecretsManager;
using Amazon.SecretsManager.Model;
using CryptoCommon.Interfaces;
using CryptoCommon.Models;
using CryptoCommon.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;

namespace CryptoCommon.Tests;

// ═══════════════════════════════════════════════════════════════════
// EcdsaCryptoService の単体テスト
// ═══════════════════════════════════════════════════════════════════

/// <summary>
/// EcdsaCryptoService の単体テスト
/// IEcdsaKeyStore をモック化してサービスの署名・検証ロジックのみを検証します。
/// </summary>
public class EcdsaCryptoServiceTests : IDisposable
{
    private readonly ECDsa _ecdsaInstance;
    private readonly EcdsaKeyPair _testKeyPair;
    private readonly Mock<IEcdsaKeyStore> _mockKeyStore;
    private readonly EcdsaCryptoService _sut;

    public EcdsaCryptoServiceTests()
    {
        // テスト全体で同じ鍵ペアを使用（署名と検証で鍵が一致していることを保証）
        _ecdsaInstance = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var privateBytes = _ecdsaInstance.ExportECPrivateKey();
        var publicBytes  = _ecdsaInstance.ExportSubjectPublicKeyInfo();

        _testKeyPair = new EcdsaKeyPair
        {
            KeyId        = "TEST0001",
            PrivateKeyPem = BuildPem("EC PRIVATE KEY", privateBytes),
            PublicKeyPem  = BuildPem("PUBLIC KEY", publicBytes),
            CreatedAt    = DateTimeOffset.UtcNow,
            Curve        = "P-256"
        };

        _mockKeyStore = new Mock<IEcdsaKeyStore>(MockBehavior.Strict);

        // GetActiveKeyPairAsync は常に _testKeyPair を返す
        _mockKeyStore
            .Setup(s => s.GetActiveKeyPairAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(_testKeyPair);

        // GetKeyPairByIdAsync("TEST0001") も同じ鍵を返す
        _mockKeyStore
            .Setup(s => s.GetKeyPairByIdAsync("TEST0001", It.IsAny<CancellationToken>()))
            .ReturnsAsync(_testKeyPair);

        _sut = new EcdsaCryptoService(_mockKeyStore.Object, NullLogger<EcdsaCryptoService>.Instance);
    }

    public void Dispose() => _ecdsaInstance.Dispose();

    // ─── SignAsync(byte[]) ─────────────────────────────────────────

    [Fact]
    public async Task SignAsync_バイト配列_正常な署名結果を返す()
    {
        var data = Encoding.UTF8.GetBytes("こんにちは、ECDSA！");

        var result = await _sut.SignAsync(data);

        Assert.NotNull(result);
        Assert.NotEmpty(result.Signature);
        Assert.Equal("TEST0001",        result.KeyId);
        Assert.Equal("SHA256withECDSA", result.Algorithm);
        Assert.True(result.SignedAt     <= DateTimeOffset.UtcNow);

        // Base64 として正常にデコードできること
        var decoded = Convert.FromBase64String(result.Signature);
        Assert.NotEmpty(decoded);
    }

    [Fact]
    public async Task SignAsync_nullバイト配列_ArgumentNullExceptionをスロー()
    {
        await Assert.ThrowsAsync<ArgumentNullException>(
            () => _sut.SignAsync((byte[])null!));
    }

    // ─── SignAsync(string) ─────────────────────────────────────────

    [Fact]
    public async Task SignAsync_文字列_正常な署名結果を返す()
    {
        var result = await _sut.SignAsync("テストデータ");

        Assert.NotNull(result);
        Assert.NotEmpty(result.Signature);
        Assert.Equal("TEST0001", result.KeyId);
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    public async Task SignAsync_nullまたは空文字列_ArgumentExceptionをスロー(string? data)
    {
        await Assert.ThrowsAsync<ArgumentException>(
            () => _sut.SignAsync(data!));
    }

    // ─── VerifyAsync ──────────────────────────────────────────────

    [Fact]
    public async Task VerifyAsync_正常な署名_trueを返す()
    {
        var data      = Encoding.UTF8.GetBytes("検証するデータ");
        var signResult = await _sut.SignAsync(data);

        var isValid = await _sut.VerifyAsync(data, signResult.Signature);

        Assert.True(isValid);
    }

    [Fact]
    public async Task VerifyAsync_改ざんされたデータ_falseを返す()
    {
        var originalData = Encoding.UTF8.GetBytes("元のデータ");
        var signResult   = await _sut.SignAsync(originalData);
        var tamperedData = Encoding.UTF8.GetBytes("改ざんされたデータ");

        var isValid = await _sut.VerifyAsync(tamperedData, signResult.Signature);

        Assert.False(isValid);
    }

    [Fact]
    public async Task VerifyAsync_不正なBase64署名_falseを返す()
    {
        var data = Encoding.UTF8.GetBytes("データ");

        var isValid = await _sut.VerifyAsync(data, "!!invalid-base64!!");

        Assert.False(isValid);
    }

    [Fact]
    public async Task VerifyAsync_ランダムバイト署名_falseを返す()
    {
        var data           = Encoding.UTF8.GetBytes("データ");
        var randomSignature = Convert.ToBase64String(RandomBytes(64));

        var isValid = await _sut.VerifyAsync(data, randomSignature);

        Assert.False(isValid);
    }

    [Fact]
    public async Task VerifyAsync_リクエストモデル_鍵IDを指定して検証()
    {
        var data      = Encoding.UTF8.GetBytes("リクエストモデルテスト");
        var signResult = await _sut.SignAsync(data);

        var request = new EcdsaVerifyRequest
        {
            Data      = data,
            Signature = signResult.Signature,
            KeyId     = "TEST0001"
        };

        var isValid = await _sut.VerifyAsync(request);

        Assert.True(isValid);
        // GetKeyPairByIdAsync が呼ばれたことを確認
        _mockKeyStore.Verify(
            s => s.GetKeyPairByIdAsync("TEST0001", It.IsAny<CancellationToken>()),
            Times.Once);
    }

    [Fact]
    public async Task VerifyAsync_KeyIdなしのリクエストモデル_アクティブ鍵で検証()
    {
        var data      = Encoding.UTF8.GetBytes("アクティブ鍵テスト");
        var signResult = await _sut.SignAsync(data);

        var request = new EcdsaVerifyRequest
        {
            Data      = data,
            Signature = signResult.Signature
            // KeyId = null → アクティブ鍵を使用
        };

        var isValid = await _sut.VerifyAsync(request);

        Assert.True(isValid);
    }

    // ─── ラウンドトリップ ──────────────────────────────────────────

    [Theory]
    [InlineData("短い文字列")]
    [InlineData("The quick brown fox jumps over the lazy dog")]
    [InlineData("{\"orderId\":\"ORD-001\",\"amount\":50000,\"currency\":\"JPY\"}")]
    [InlineData("日本語のペイロードテスト: 署名・検証")]
    public async Task SignAndVerify_ラウンドトリップ_常に成功(string payload)
    {
        var data      = Encoding.UTF8.GetBytes(payload);
        var signResult = await _sut.SignAsync(data);

        var isValid = await _sut.VerifyAsync(data, signResult.Signature);

        Assert.True(isValid);
    }

    [Fact]
    public async Task SignAsync_複数回呼び出し_毎回異なる署名を返す()
    {
        // ECDSA は確率的アルゴリズムなので、同じデータでも署名ごとに異なる値になる
        var data = Encoding.UTF8.GetBytes("同じデータ");

        var result1 = await _sut.SignAsync(data);
        var result2 = await _sut.SignAsync(data);

        // 署名値は確率的に異なる（同一である確率は無視できるほど低い）
        Assert.NotEqual(result1.Signature, result2.Signature);

        // 両方の署名が元データに対して有効であること
        Assert.True(await _sut.VerifyAsync(data, result1.Signature));
        Assert.True(await _sut.VerifyAsync(data, result2.Signature));
    }

    // ─── ヘルパー ──────────────────────────────────────────────────

    private static string BuildPem(string label, byte[] derBytes) =>
        $"-----BEGIN {label}-----\n{Convert.ToBase64String(derBytes, Base64FormattingOptions.InsertLineBreaks)}\n-----END {label}-----";

    private static byte[] RandomBytes(int length)
    {
        var bytes = new byte[length];
        Random.Shared.NextBytes(bytes);
        return bytes;
    }
}

// ═══════════════════════════════════════════════════════════════════
// AwsEcdsaKeyStore の単体テスト
// ═══════════════════════════════════════════════════════════════════

/// <summary>
/// AwsEcdsaKeyStore の単体テスト
/// IAmazonSecretsManager をモック化して鍵の取得・キャッシュ・エラー処理を検証します。
/// </summary>
public class AwsEcdsaKeyStoreTests : IAsyncDisposable
{
    private readonly Mock<IAmazonSecretsManager> _mockSm;
    private readonly AwsKeyStoreOptions _options;
    private readonly AwsEcdsaKeyStore _sut;

    public AwsEcdsaKeyStoreTests()
    {
        _mockSm = new Mock<IAmazonSecretsManager>(MockBehavior.Strict);

        _options = new AwsKeyStoreOptions
        {
            ActiveKeySecretName = "test/ecdsa/active-key",
            KeySecretPrefix     = "test/ecdsa/keys",
            CacheTtl            = TimeSpan.FromMinutes(5),
            AwsRegion           = "ap-northeast-1"
        };

        _sut = new AwsEcdsaKeyStore(
            _mockSm.Object,
            NullLogger<AwsEcdsaKeyStore>.Instance,
            _options);
    }

    public async ValueTask DisposeAsync() => await _sut.DisposeAsync();

    // ─── GetActiveKeyPairAsync ─────────────────────────────────────

    [Fact]
    public async Task GetActiveKeyPairAsync_正常なシークレット_デシリアライズして返す()
    {
        var keyPair = CreateTestKeyPair("ABCD1234");
        SetupGetSecret(_options.ActiveKeySecretName, keyPair);

        var result = await _sut.GetActiveKeyPairAsync();

        Assert.Equal(keyPair.KeyId,  result.KeyId);
        Assert.Equal(keyPair.Curve,  result.Curve);
        Assert.Equal(keyPair.PublicKeyPem, result.PublicKeyPem);
    }

    [Fact]
    public async Task GetActiveKeyPairAsync_2回目の呼び出し_キャッシュから返す()
    {
        var keyPair = CreateTestKeyPair("CACHE001");
        SetupGetSecret(_options.ActiveKeySecretName, keyPair);

        // 1回目: AWS から取得
        var result1 = await _sut.GetActiveKeyPairAsync();
        // 2回目: キャッシュから返す
        var result2 = await _sut.GetActiveKeyPairAsync();

        Assert.Equal(result1.KeyId, result2.KeyId);

        // AWS SDK は1回だけ呼ばれること
        _mockSm.Verify(
            s => s.GetSecretValueAsync(
                It.IsAny<GetSecretValueRequest>(),
                It.IsAny<CancellationToken>()),
            Times.Once);
    }

    [Fact]
    public async Task GetActiveKeyPairAsync_シークレットが存在しない_KeyNotFoundExceptionをスロー()
    {
        // ResourceNotFoundException は string + Exception の2引数コンストラクタを使用
        var innerEx = new Exception("AWS エラー");
        _mockSm
            .Setup(s => s.GetSecretValueAsync(
                It.IsAny<GetSecretValueRequest>(),
                It.IsAny<CancellationToken>()))
            .ThrowsAsync(new ResourceNotFoundException("見つかりません", innerEx));

        await Assert.ThrowsAsync<KeyNotFoundException>(
            () => _sut.GetActiveKeyPairAsync());
    }

    // ─── GetKeyPairByIdAsync ───────────────────────────────────────

    [Fact]
    public async Task GetKeyPairByIdAsync_正しいシークレット名で取得する()
    {
        var keyId   = "EFGH5678";
        var keyPair = CreateTestKeyPair(keyId);
        var expectedSecretName = $"{_options.KeySecretPrefix}/{keyId}";
        SetupGetSecret(expectedSecretName, keyPair);

        var result = await _sut.GetKeyPairByIdAsync(keyId);

        Assert.Equal(keyId, result.KeyId);

        // 正しいシークレット名で呼ばれたことを確認
        _mockSm.Verify(
            s => s.GetSecretValueAsync(
                It.Is<GetSecretValueRequest>(r => r.SecretId == expectedSecretName),
                It.IsAny<CancellationToken>()),
            Times.Once);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public async Task GetKeyPairByIdAsync_空または空白の鍵ID_ArgumentExceptionをスロー(string keyId)
    {
        await Assert.ThrowsAsync<ArgumentException>(
            () => _sut.GetKeyPairByIdAsync(keyId));
    }

    // ─── ヘルパーメソッド ──────────────────────────────────────────

    /// <summary>テスト用の ECDSA 鍵ペアを生成します。</summary>
    private static EcdsaKeyPair CreateTestKeyPair(string keyId)
    {
        using var ecdsa  = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var privateBytes = ecdsa.ExportECPrivateKey();
        var publicBytes  = ecdsa.ExportSubjectPublicKeyInfo();

        return new EcdsaKeyPair
        {
            KeyId        = keyId,
            PrivateKeyPem = BuildPem("EC PRIVATE KEY", privateBytes),
            PublicKeyPem  = BuildPem("PUBLIC KEY",     publicBytes),
            CreatedAt    = DateTimeOffset.UtcNow,
            Curve        = "P-256"
        };
    }

    /// <summary>
    /// GetSecretValueAsync のモックをセットアップします。
    /// GetSecretValueResponse はオブジェクト初期化子で生成可能です。
    /// </summary>
    private void SetupGetSecret(string secretName, EcdsaKeyPair keyPair)
    {
        var response = new GetSecretValueResponse
        {
            SecretString = JsonSerializer.Serialize(keyPair),
            ARN          = $"arn:aws:secretsmanager:ap-northeast-1:123456789:secret:{secretName}",
            Name         = secretName,
            VersionId    = Guid.NewGuid().ToString()
        };

        _mockSm
            .Setup(s => s.GetSecretValueAsync(
                It.Is<GetSecretValueRequest>(r => r.SecretId == secretName),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(response);
    }

    private static string BuildPem(string label, byte[] derBytes) =>
        $"-----BEGIN {label}-----\n{Convert.ToBase64String(derBytes, Base64FormattingOptions.InsertLineBreaks)}\n-----END {label}-----";
}
