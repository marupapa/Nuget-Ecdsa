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

/// <summary>
/// EcdsaCryptoService 단위 테스트
/// </summary>
public class EcdsaCryptoServiceTests
{
    private readonly IEcdsaKeyStore _keyStore;
    private readonly EcdsaCryptoService _sut;
    private readonly EcdsaKeyPair _testKeyPair;

    public EcdsaCryptoServiceTests()
    {
        // 테스트용 실제 ECDSA 키 페어 생성
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var privateKeyBytes = ecdsa.ExportECPrivateKey();
        var publicKeyBytes  = ecdsa.ExportSubjectPublicKeyInfo();

        _testKeyPair = new EcdsaKeyPair
        {
            KeyId        = "TEST0001",
            PrivateKeyPem = $"-----BEGIN EC PRIVATE KEY-----\n{Convert.ToBase64String(privateKeyBytes, Base64FormattingOptions.InsertLineBreaks)}\n-----END EC PRIVATE KEY-----",
            PublicKeyPem  = $"-----BEGIN PUBLIC KEY-----\n{Convert.ToBase64String(publicKeyBytes, Base64FormattingOptions.InsertLineBreaks)}\n-----END PUBLIC KEY-----",
            CreatedAt    = DateTimeOffset.UtcNow,
            Curve        = "P-256"
        };

        var mockKeyStore = new Mock<IEcdsaKeyStore>();
        mockKeyStore
            .Setup(s => s.GetActiveKeyPairAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(_testKeyPair);
        mockKeyStore
            .Setup(s => s.GetKeyPairByIdAsync("TEST0001", It.IsAny<CancellationToken>()))
            .ReturnsAsync(_testKeyPair);

        _keyStore = mockKeyStore.Object;
        _sut = new EcdsaCryptoService(_keyStore, NullLogger<EcdsaCryptoService>.Instance);
    }

    // ─── SignAsync (byte[]) ────────────────────────────────────────────────────

    [Fact]
    public async Task SignAsync_WithBytes_ReturnsValidResult()
    {
        // Arrange
        var data = Encoding.UTF8.GetBytes("Hello, ECDSA!");

        // Act
        var result = await _sut.SignAsync(data);

        // Assert
        Assert.NotNull(result);
        Assert.NotEmpty(result.Signature);
        Assert.Equal("TEST0001", result.KeyId);
        Assert.Equal("SHA256withECDSA", result.Algorithm);
        Assert.True(result.SignedAt <= DateTimeOffset.UtcNow);
    }

    [Fact]
    public async Task SignAsync_WithNullBytes_ThrowsArgumentNullException()
    {
        await Assert.ThrowsAsync<ArgumentNullException>(() => _sut.SignAsync((byte[])null!));
    }

    // ─── SignAsync (string) ────────────────────────────────────────────────────

    [Fact]
    public async Task SignAsync_WithString_ReturnsValidResult()
    {
        var result = await _sut.SignAsync("테스트 데이터");

        Assert.NotNull(result);
        Assert.NotEmpty(result.Signature);
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    public async Task SignAsync_WithNullOrEmptyString_ThrowsArgumentException(string? data)
    {
        await Assert.ThrowsAsync<ArgumentException>(() => _sut.SignAsync(data!));
    }

    // ─── VerifyAsync ──────────────────────────────────────────────────────────

    [Fact]
    public async Task VerifyAsync_ValidSignature_ReturnsTrue()
    {
        // Arrange
        var data = Encoding.UTF8.GetBytes("검증할 데이터");
        var signResult = await _sut.SignAsync(data);

        // Act
        var isValid = await _sut.VerifyAsync(data, signResult.Signature);

        // Assert
        Assert.True(isValid);
    }

    [Fact]
    public async Task VerifyAsync_TamperedData_ReturnsFalse()
    {
        // Arrange
        var originalData = Encoding.UTF8.GetBytes("원본 데이터");
        var signResult   = await _sut.SignAsync(originalData);
        var tamperedData = Encoding.UTF8.GetBytes("변조된 데이터");

        // Act
        var isValid = await _sut.VerifyAsync(tamperedData, signResult.Signature);

        // Assert
        Assert.False(isValid);
    }

    [Fact]
    public async Task VerifyAsync_InvalidBase64Signature_ReturnsFalse()
    {
        var data = Encoding.UTF8.GetBytes("데이터");
        var isValid = await _sut.VerifyAsync(data, "not-valid-base64!!!");
        Assert.False(isValid);
    }

    [Fact]
    public async Task VerifyAsync_WithRequest_UsesKeyId()
    {
        // Arrange
        var data       = Encoding.UTF8.GetBytes("데이터");
        var signResult = await _sut.SignAsync(data);

        var request = new EcdsaVerifyRequest
        {
            Data      = data,
            Signature = signResult.Signature,
            KeyId     = "TEST0001"
        };

        // Act
        var isValid = await _sut.VerifyAsync(request);

        // Assert
        Assert.True(isValid);
    }

    // ─── Round-trip ───────────────────────────────────────────────────────────

    [Theory]
    [InlineData("짧은 문자열")]
    [InlineData("The quick brown fox jumps over the lazy dog")]
    [InlineData("{\"orderId\":\"ORD-001\",\"amount\":50000,\"currency\":\"KRW\"}")]
    public async Task SignAndVerify_RoundTrip_Succeeds(string payload)
    {
        var data       = Encoding.UTF8.GetBytes(payload);
        var signResult = await _sut.SignAsync(data);
        var isValid    = await _sut.VerifyAsync(data, signResult.Signature);

        Assert.True(isValid);
    }
}

/// <summary>
/// AwsEcdsaKeyStore 단위 테스트 (AWS SDK Mocking)
/// </summary>
public class AwsEcdsaKeyStoreTests
{
    private readonly Mock<IAmazonSecretsManager> _mockSecretsManager;
    private readonly AwsKeyStoreOptions _options;
    private readonly AwsEcdsaKeyStore _sut;

    public AwsEcdsaKeyStoreTests()
    {
        _mockSecretsManager = new Mock<IAmazonSecretsManager>();
        _options = new AwsKeyStoreOptions
        {
            ActiveKeySecretName = "test/ecdsa/active-key",
            KeySecretPrefix     = "test/ecdsa/keys",
            CacheTtl            = TimeSpan.FromMinutes(5),
            AwsRegion           = "ap-northeast-2"
        };

        _sut = new AwsEcdsaKeyStore(
            _mockSecretsManager.Object,
            NullLogger<AwsEcdsaKeyStore>.Instance,
            _options);
    }

    [Fact]
    public async Task GetActiveKeyPairAsync_ReturnsDeserializedKeyPair()
    {
        // Arrange
        var expectedKeyPair = CreateTestKeyPair("ABCD1234");
        SetupGetSecretValue(_options.ActiveKeySecretName, expectedKeyPair);

        // Act
        var result = await _sut.GetActiveKeyPairAsync();

        // Assert
        Assert.Equal(expectedKeyPair.KeyId, result.KeyId);
        Assert.Equal(expectedKeyPair.Curve,  result.Curve);
    }

    [Fact]
    public async Task GetActiveKeyPairAsync_SecondCall_UsesCachedValue()
    {
        // Arrange
        var keyPair = CreateTestKeyPair("CACHE001");
        SetupGetSecretValue(_options.ActiveKeySecretName, keyPair);

        // Act - 두 번 호출
        await _sut.GetActiveKeyPairAsync();
        await _sut.GetActiveKeyPairAsync();

        // Assert - AWS SDK는 1번만 호출되어야 함
        _mockSecretsManager.Verify(
            s => s.GetSecretValueAsync(It.IsAny<GetSecretValueRequest>(), It.IsAny<CancellationToken>()),
            Times.Once);
    }

    [Fact]
    public async Task GetKeyPairByIdAsync_ReturnsCorrectKeyPair()
    {
        // Arrange
        var keyId   = "EFGH5678";
        var keyPair = CreateTestKeyPair(keyId);
        SetupGetSecretValue($"{_options.KeySecretPrefix}/{keyId}", keyPair);

        // Act
        var result = await _sut.GetKeyPairByIdAsync(keyId);

        // Assert
        Assert.Equal(keyId, result.KeyId);
    }

    [Fact]
    public async Task GetKeyPairByIdAsync_EmptyKeyId_ThrowsArgumentException()
    {
        await Assert.ThrowsAsync<ArgumentException>(() => _sut.GetKeyPairByIdAsync(""));
    }

    [Fact]
    public async Task GetActiveKeyPairAsync_SecretNotFound_ThrowsKeyNotFoundException()
    {
        // Arrange
        _mockSecretsManager
            .Setup(s => s.GetSecretValueAsync(It.IsAny<GetSecretValueRequest>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new ResourceNotFoundException("Not found"));

        // Act & Assert
        await Assert.ThrowsAsync<KeyNotFoundException>(() => _sut.GetActiveKeyPairAsync());
    }

    // ─── Helpers ──────────────────────────────────────────────────────────────

    private static EcdsaKeyPair CreateTestKeyPair(string keyId)
    {
        using var ecdsa   = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var privateBytes  = ecdsa.ExportECPrivateKey();
        var publicBytes   = ecdsa.ExportSubjectPublicKeyInfo();

        return new EcdsaKeyPair
        {
            KeyId        = keyId,
            PrivateKeyPem = $"-----BEGIN EC PRIVATE KEY-----\n{Convert.ToBase64String(privateBytes, Base64FormattingOptions.InsertLineBreaks)}\n-----END EC PRIVATE KEY-----",
            PublicKeyPem  = $"-----BEGIN PUBLIC KEY-----\n{Convert.ToBase64String(publicBytes, Base64FormattingOptions.InsertLineBreaks)}\n-----END PUBLIC KEY-----",
            CreatedAt    = DateTimeOffset.UtcNow,
            Curve        = "P-256"
        };
    }

    private void SetupGetSecretValue(string secretName, EcdsaKeyPair keyPair)
    {
        _mockSecretsManager
            .Setup(s => s.GetSecretValueAsync(
                It.Is<GetSecretValueRequest>(r => r.SecretId == secretName),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new GetSecretValueResponse
            {
                SecretString = JsonSerializer.Serialize(keyPair)
            });
    }
}
