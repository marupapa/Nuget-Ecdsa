namespace CryptoCommon.Models;

/// <summary>
/// AWS Secrets Manager에 저장되는 ECDSA 키 페어 모델
/// .NET 10: record + required 멤버 활용
/// </summary>
public record EcdsaKeyPair
{
    /// <summary>키 버전 또는 식별자</summary>
    public required string KeyId { get; init; }

    /// <summary>PEM 형식의 개인키</summary>
    public required string PrivateKeyPem { get; init; }

    /// <summary>PEM 형식의 공개키</summary>
    public required string PublicKeyPem { get; init; }

    /// <summary>키 생성 일시 (UTC)</summary>
    public DateTimeOffset CreatedAt { get; init; } = DateTimeOffset.UtcNow;

    /// <summary>사용할 곡선 알고리즘 (기본: P-256)</summary>
    public string Curve { get; init; } = "P-256";
}

/// <summary>
/// ECDSA 서명 결과 모델
/// .NET 10: Positional record로 불변성 보장
/// </summary>
public record EcdsaSignatureResult(
    string Signature,
    string KeyId,
    string Algorithm,
    DateTimeOffset SignedAt);

/// <summary>
/// 서명 검증 요청 모델
/// </summary>
public record EcdsaVerifyRequest
{
    /// <summary>원본 데이터 (바이트 배열)</summary>
    public required byte[] Data { get; init; }

    /// <summary>Base64 인코딩된 서명값</summary>
    public required string Signature { get; init; }

    /// <summary>검증에 사용할 키 ID (null이면 활성 키 사용)</summary>
    public string? KeyId { get; init; }
}
