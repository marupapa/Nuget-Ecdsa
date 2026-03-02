using CryptoCommon.Models;

namespace CryptoCommon.Interfaces;

/// <summary>
/// AWS Secrets Manager에서 ECDSA 키를 관리하는 인터페이스
/// </summary>
public interface IEcdsaKeyStore
{
    /// <summary>현재 활성 키 페어를 가져옵니다.</summary>
    Task<EcdsaKeyPair> GetActiveKeyPairAsync(CancellationToken cancellationToken = default);

    /// <summary>특정 키 ID로 키 페어를 가져옵니다.</summary>
    Task<EcdsaKeyPair> GetKeyPairByIdAsync(string keyId, CancellationToken cancellationToken = default);

    /// <summary>새 키 페어를 생성하고 Secrets Manager에 저장합니다.</summary>
    Task<EcdsaKeyPair> GenerateAndStoreKeyPairAsync(CancellationToken cancellationToken = default);

    /// <summary>기존 키 페어를 교체합니다 (로테이션).</summary>
    Task<EcdsaKeyPair> RotateKeyPairAsync(CancellationToken cancellationToken = default);
}

/// <summary>
/// ECDSA 서명 및 검증 서비스 인터페이스
/// </summary>
public interface IEcdsaCryptoService
{
    /// <summary>데이터에 서명합니다 (활성 키 사용).</summary>
    Task<EcdsaSignatureResult> SignAsync(byte[] data, CancellationToken cancellationToken = default);

    /// <summary>문자열 데이터에 서명합니다.</summary>
    Task<EcdsaSignatureResult> SignAsync(string data, CancellationToken cancellationToken = default);

    /// <summary>서명 요청 모델로 검증합니다.</summary>
    Task<bool> VerifyAsync(EcdsaVerifyRequest request, CancellationToken cancellationToken = default);

    /// <summary>데이터와 서명값으로 검증합니다 (활성 키 사용).</summary>
    Task<bool> VerifyAsync(byte[] data, string signature, CancellationToken cancellationToken = default);
}
