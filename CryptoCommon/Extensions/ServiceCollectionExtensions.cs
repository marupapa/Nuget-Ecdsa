using Amazon;
using Amazon.SecretsManager;
using CryptoCommon.Interfaces;
using CryptoCommon.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace CryptoCommon.Extensions;

/// <summary>
/// CryptoCommon 서비스 DI 등록 확장 메서드
/// .NET 10: IOptions 패턴 활용
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// ECDSA 암호화 공통모듈을 DI 컨테이너에 등록합니다.
    /// </summary>
    /// <example>
    /// builder.Services.AddEcdsaCrypto(options =>
    /// {
    ///     options.ActiveKeySecretName = "myapp/ecdsa/active-key";
    ///     options.KeySecretPrefix     = "myapp/ecdsa/keys";
    ///     options.AwsRegion           = "ap-northeast-2";
    ///     options.CacheTtl            = TimeSpan.FromMinutes(10);
    /// });
    /// </example>
    public static IServiceCollection AddEcdsaCrypto(
        this IServiceCollection services,
        Action<AwsKeyStoreOptions>? configure = null)
    {
        // IOptions<T> 패턴으로 옵션 등록
        var optionsBuilder = services.AddOptions<AwsKeyStoreOptions>();
        if (configure is not null)
            optionsBuilder.Configure(configure);

        // AWS Secrets Manager 클라이언트
        services.TryAddSingleton<IAmazonSecretsManager>(sp =>
        {
            var opts = sp.GetRequiredService<IOptions<AwsKeyStoreOptions>>().Value;
            return new AmazonSecretsManagerClient(RegionEndpoint.GetBySystemName(opts.AwsRegion));
        });

        // AwsKeyStoreOptions 직접 주입용
        services.TryAddSingleton(sp =>
            sp.GetRequiredService<IOptions<AwsKeyStoreOptions>>().Value);

        // 핵심 서비스 등록
        services.AddSingleton<IEcdsaKeyStore, AwsEcdsaKeyStore>();
        services.AddScoped<IEcdsaCryptoService, EcdsaCryptoService>();

        return services;
    }
}
