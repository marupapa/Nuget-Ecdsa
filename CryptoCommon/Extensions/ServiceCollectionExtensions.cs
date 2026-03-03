using Amazon;
using Amazon.SecretsManager;
using CryptoCommon.Interfaces;
using CryptoCommon.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace CryptoCommon.Extensions;

/// <summary>
/// CryptoCommon サービスの DI 登録拡張メソッド
/// .NET 10: IOptions パターンを活用
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// ECDSA 暗号化共通モジュールを DI コンテナに登録します。
    /// </summary>
    /// <example>
    /// builder.Services.AddEcdsaCrypto(options =>
    /// {
    ///     options.ActiveKeySecretName = "myapp/ecdsa/active-key";
    ///     options.KeySecretPrefix     = "myapp/ecdsa/keys";
    ///     options.AwsRegion           = "ap-northeast-1";
    ///     options.CacheTtl            = TimeSpan.FromMinutes(10);
    /// });
    /// </example>
    public static IServiceCollection AddEcdsaCrypto(
        this IServiceCollection services,
        Action<AwsKeyStoreOptions>? configure = null)
    {
        // IOptions<T> パターンでオプションを登録
        var optionsBuilder = services.AddOptions<AwsKeyStoreOptions>();
        if (configure is not null)
            optionsBuilder.Configure(configure);

        // AWS Secrets Manager クライアント
        services.TryAddSingleton<IAmazonSecretsManager>(sp =>
        {
            var opts = sp.GetRequiredService<IOptions<AwsKeyStoreOptions>>().Value;
            return new AmazonSecretsManagerClient(RegionEndpoint.GetBySystemName(opts.AwsRegion));
        });

        // AwsKeyStoreOptions の直接注入用
        services.TryAddSingleton(sp =>
            sp.GetRequiredService<IOptions<AwsKeyStoreOptions>>().Value);

        // コアサービスの登録
        services.AddSingleton<IEcdsaKeyStore, AwsEcdsaKeyStore>();
        services.AddScoped<IEcdsaCryptoService, EcdsaCryptoService>();

        return services;
    }
}
