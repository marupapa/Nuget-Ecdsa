namespace CryptoCommon.Models;

/// <summary>
/// AWS Secrets Manager に保存される ECDSA 鍵ペアモデル
/// .NET 10: record + required メンバーを活用
/// </summary>
public record EcdsaKeyPair
{
    /// <summary>鍵のバージョンまたは識別子</summary>
    public required string KeyId { get; init; }

    /// <summary>PEM 形式の秘密鍵</summary>
    public required string PrivateKeyPem { get; init; }

    /// <summary>PEM 形式の公開鍵</summary>
    public required string PublicKeyPem { get; init; }

    /// <summary>鍵の生成日時（UTC）</summary>
    public DateTimeOffset CreatedAt { get; init; } = DateTimeOffset.UtcNow;

    /// <summary>使用する楕円曲線アルゴリズム（デフォルト: P-256）</summary>
    public string Curve { get; init; } = "P-256";
}

/// <summary>
/// ECDSA 署名結果モデル
/// .NET 10: Positional record で不変性を保証
/// </summary>
public record EcdsaSignatureResult(
    string Signature,
    string KeyId,
    string Algorithm,
    DateTimeOffset SignedAt);

/// <summary>
/// 署名検証リクエストモデル
/// </summary>
public record EcdsaVerifyRequest
{
    /// <summary>元データ（バイト配列）</summary>
    public required byte[] Data { get; init; }

    /// <summary>Base64 エンコードされた署名値</summary>
    public required string Signature { get; init; }

    /// <summary>検証に使用する鍵ID（null の場合はアクティブ鍵を使用）</summary>
    public string? KeyId { get; init; }
}
