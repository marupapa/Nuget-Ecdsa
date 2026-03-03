using System.Security.Cryptography;
using System.Text;
using CryptoCommon.Interfaces;
using CryptoCommon.Models;
using Microsoft.Extensions.Logging;

namespace CryptoCommon.Services;

/// <summary>
/// ECDSA 署名・検証サービス
/// .NET 10: Primary Constructor、ImportFromPem()、式本体メソッドを活用
/// </summary>
public sealed class EcdsaCryptoService(
    IEcdsaKeyStore keyStore,
    ILogger<EcdsaCryptoService> logger) : IEcdsaCryptoService
{
    /// <inheritdoc/>
    public async Task<EcdsaSignatureResult> SignAsync(byte[] data, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(data);

        var keyPair = await keyStore.GetActiveKeyPairAsync(cancellationToken);

        using var ecdsa = LoadPrivateKey(keyPair.PrivateKeyPem);

        // SHA-256 ハッシュ + RFC 3279 DER エンコード署名
        var signature = ecdsa.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

        logger.LogDebug("ECDSA 署名完了 (KeyId: {KeyId}, {Length}バイト)", keyPair.KeyId, data.Length);

        return new EcdsaSignatureResult(
            Signature: Convert.ToBase64String(signature),
            KeyId: keyPair.KeyId,
            Algorithm: "SHA256withECDSA",
            SignedAt: DateTimeOffset.UtcNow);
    }

    /// <inheritdoc/>
    public async Task<EcdsaSignatureResult> SignAsync(string data, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(data);
        return await SignAsync(Encoding.UTF8.GetBytes(data), cancellationToken);
    }

    /// <inheritdoc/>
    public async Task<bool> VerifyAsync(EcdsaVerifyRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var keyPair = string.IsNullOrEmpty(request.KeyId)
            ? await keyStore.GetActiveKeyPairAsync(cancellationToken)
            : await keyStore.GetKeyPairByIdAsync(request.KeyId, cancellationToken);

        using var ecdsa = LoadPublicKey(keyPair.PublicKeyPem);

        try
        {
            var signatureBytes = Convert.FromBase64String(request.Signature);
            var isValid = ecdsa.VerifyData(
                request.Data,
                signatureBytes,
                HashAlgorithmName.SHA256,
                DSASignatureFormat.Rfc3279DerSequence);

            logger.LogDebug("署名検証: {Result} (KeyId: {KeyId})", isValid ? "有効" : "無効", keyPair.KeyId);
            return isValid;
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "署名検証中にエラーが発生 (KeyId: {KeyId})", keyPair.KeyId);
            return false;
        }
    }

    /// <inheritdoc/>
    public async Task<bool> VerifyAsync(byte[] data, string signature, CancellationToken cancellationToken = default) =>
        await VerifyAsync(new EcdsaVerifyRequest { Data = data, Signature = signature }, cancellationToken);

    // ─── プライベートヘルパー ──────────────────────────────────────────────────

    private static ECDsa LoadPrivateKey(string privateKeyPem)
    {
        var ecdsa = ECDsa.Create();
        try
        {
            // .NET 10: ImportFromPem - PEM ヘッダー/フッターを自動処理
            ecdsa.ImportFromPem(privateKeyPem);
            return ecdsa;
        }
        catch
        {
            ecdsa.Dispose();
            throw;
        }
    }

    private static ECDsa LoadPublicKey(string publicKeyPem)
    {
        var ecdsa = ECDsa.Create();
        try
        {
            ecdsa.ImportFromPem(publicKeyPem);
            return ecdsa;
        }
        catch
        {
            ecdsa.Dispose();
            throw;
        }
    }
}
