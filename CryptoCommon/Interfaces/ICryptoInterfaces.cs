using CryptoCommon.Models;

namespace CryptoCommon.Interfaces;

/// <summary>
/// AWS Secrets Manager で ECDSA 鍵を管理するインターフェース
/// </summary>
public interface IEcdsaKeyStore
{
    /// <summary>現在のアクティブな鍵ペアを取得します。</summary>
    Task<EcdsaKeyPair> GetActiveKeyPairAsync(CancellationToken cancellationToken = default);

    /// <summary>特定の鍵IDで鍵ペアを取得します。</summary>
    Task<EcdsaKeyPair> GetKeyPairByIdAsync(string keyId, CancellationToken cancellationToken = default);

    /// <summary>新しい鍵ペアを生成し、Secrets Manager に保存します。</summary>
    Task<EcdsaKeyPair> GenerateAndStoreKeyPairAsync(CancellationToken cancellationToken = default);

    /// <summary>既存の鍵ペアをローテーションします。</summary>
    Task<EcdsaKeyPair> RotateKeyPairAsync(CancellationToken cancellationToken = default);
}

/// <summary>
/// ECDSA 署名・検証サービスインターフェース
/// </summary>
public interface IEcdsaCryptoService
{
    /// <summary>データに署名します（アクティブ鍵を使用）。</summary>
    Task<EcdsaSignatureResult> SignAsync(byte[] data, CancellationToken cancellationToken = default);

    /// <summary>文字列データに署名します。</summary>
    Task<EcdsaSignatureResult> SignAsync(string data, CancellationToken cancellationToken = default);

    /// <summary>署名リクエストモデルで検証します。</summary>
    Task<bool> VerifyAsync(EcdsaVerifyRequest request, CancellationToken cancellationToken = default);

    /// <summary>データと署名値で検証します（アクティブ鍵を使用）。</summary>
    Task<bool> VerifyAsync(byte[] data, string signature, CancellationToken cancellationToken = default);
}
