# CryptoCommon.Ecdsa

[![NuGet](https://img.shields.io/nuget/v/CryptoCommon.Ecdsa.svg)](https://www.nuget.org/packages/CryptoCommon.Ecdsa)
[![NuGet Downloads](https://img.shields.io/nuget/dt/CryptoCommon.Ecdsa.svg)](https://www.nuget.org/packages/CryptoCommon.Ecdsa)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![.NET](https://img.shields.io/badge/.NET-10.0-purple.svg)](https://dotnet.microsoft.com)

**.NET 10** ベースの **ECDSA（P-256）署名・検証共通モジュール**です。  
暗号鍵を **AWS Secrets Manager** に安全に保管し、鍵のキャッシュ・ローテーション・履歴管理をサポートします。

---

## 目次

- [インストール](#インストール)
- [アーキテクチャ](#アーキテクチャ)
- [クイックスタート](#クイックスタート)
- [API リファレンス](#api-リファレンス)
- [AWS 設定](#aws-設定)
- [.NET 10 主要機能](#net-10-主要適用機能)
- [プロジェクト構造](#プロジェクト構造)
- [テスト実行](#テスト実行)
- [NuGet 公開ガイド](#nuget-公開ガイド)
- [ライセンス](#ライセンス)

---

## インストール

```bash
dotnet add package CryptoCommon.Ecdsa
```

または `csproj` に直接追加:

```xml
<PackageReference Include="CryptoCommon.Ecdsa" Version="2.0.0" />
```

---

## アーキテクチャ

```
┌──────────────────────────────────────────────────┐
│                   アプリケーション                  │
│                                                  │
│  IEcdsaCryptoService  ──→  EcdsaCryptoService    │
│         │                        │               │
│         │               IEcdsaKeyStore           │
│         │                        │               │
│         └────────────────→  AwsEcdsaKeyStore     │
│                                  │               │
└──────────────────────────────────┼───────────────┘
                                   │
                    ┌──────────────▼──────────────┐
                    │   AWS Secrets Manager       │
                    │                             │
                    │  crypto/ecdsa/active-key    │ ← 現在のアクティブ鍵
                    │  crypto/ecdsa/keys/{keyId}  │ ← 鍵の履歴
                    └─────────────────────────────┘
```

---

## クイックスタート

### 1. DI 登録（Program.cs）

```csharp
using CryptoCommon.Extensions;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddEcdsaCrypto(options =>
{
    options.ActiveKeySecretName = "myapp/ecdsa/active-key";  // アクティブ鍵のシークレット名
    options.KeySecretPrefix     = "myapp/ecdsa/keys";        // 鍵履歴パスのプレフィックス
    options.AwsRegion           = "ap-northeast-1";          // AWSリージョン
    options.CacheTtl            = TimeSpan.FromMinutes(5);   // キャッシュTTL
    options.Tags = new()
    {
        ["Application"] = "MyApp",
        ["Environment"] = "Production"
    };
});
```

### 2. 初回鍵生成

アプリ初回起動時に1回だけ実行し、AWS Secrets Manager に鍵を保存します。

```csharp
await using var scope = app.Services.CreateAsyncScope();
var keyStore = scope.ServiceProvider.GetRequiredService<IEcdsaKeyStore>();
await keyStore.GenerateAndStoreKeyPairAsync();
```

### 3. 署名

```csharp
public class PaymentService(IEcdsaCryptoService crypto)
{
    public async Task<string> SignPayloadAsync(string payload)
    {
        var result = await crypto.SignAsync(payload);

        Console.WriteLine(result.Signature);   // Base64エンコードされた署名値
        Console.WriteLine(result.KeyId);       // 署名に使用した鍵ID
        Console.WriteLine(result.SignedAt);    // 署名日時（DateTimeOffset UTC）

        return result.Signature;
    }
}
```

### 4. 検証

```csharp
// 方法1: アクティブ鍵でシンプルに検証
bool isValid = await crypto.VerifyAsync(dataBytes, signatureBase64);

// 方法2: 特定の鍵IDで検証（鍵ローテーション後も過去の署名を検証可能）
bool isValid = await crypto.VerifyAsync(new EcdsaVerifyRequest
{
    Data      = Encoding.UTF8.GetBytes(payload),
    Signature = signatureBase64,
    KeyId     = "A1B2C3D4"   // null の場合はアクティブ鍵を使用
});
```

### 5. 鍵ローテーション

```csharp
// 新しい鍵を生成 → アクティブ鍵を切り替え（旧鍵は履歴に保存され、過去の署名も検証可能）
var newKey = await keyStore.RotateKeyPairAsync();
Console.WriteLine($"新しい鍵ID: {newKey.KeyId}");
```

---

## API リファレンス

### IEcdsaCryptoService

| メソッド | 説明 |
|---------|------|
| `SignAsync(byte[] data)` | バイト配列に署名 |
| `SignAsync(string data)` | 文字列に署名（UTF-8エンコード） |
| `VerifyAsync(byte[] data, string signature)` | アクティブ鍵で署名を検証 |
| `VerifyAsync(EcdsaVerifyRequest request)` | 特定の鍵IDで署名を検証 |

### IEcdsaKeyStore

| メソッド | 説明 |
|---------|------|
| `GetActiveKeyPairAsync()` | 現在のアクティブ鍵を取得（キャッシュあり） |
| `GetKeyPairByIdAsync(string keyId)` | 特定の鍵IDで鍵ペアを取得 |
| `GenerateAndStoreKeyPairAsync()` | 新しい鍵を生成して保存 |
| `RotateKeyPairAsync()` | 鍵ローテーション（新鍵生成 + アクティブ鍵切り替え） |

### EcdsaSignatureResult

```csharp
public record EcdsaSignatureResult(
    string Signature,       // Base64エンコードされた署名値
    string KeyId,           // 署名に使用した鍵ID
    string Algorithm,       // "SHA256withECDSA"
    DateTimeOffset SignedAt // 署名日時（UTC）
);
```

### AwsKeyStoreOptions

```csharp
public sealed class AwsKeyStoreOptions
{
    public string ActiveKeySecretName { get; set; } = "crypto/ecdsa/active-key";
    public string KeySecretPrefix     { get; set; } = "crypto/ecdsa/keys";
    public TimeSpan CacheTtl          { get; set; } = TimeSpan.FromMinutes(5);
    public string AwsRegion           { get; set; } = "ap-northeast-1";
    public Dictionary<string, string> Tags { get; set; }
}
```

---

## AWS 設定

### Secrets Manager 保存形式

```json
{
  "KeyId":         "A1B2C3D4",
  "PrivateKeyPem": "-----BEGIN EC PRIVATE KEY-----\n...\n-----END EC PRIVATE KEY-----",
  "PublicKeyPem":  "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
  "CreatedAt":     "2025-01-01T00:00:00+00:00",
  "Curve":         "P-256"
}
```

### 最小 IAM 権限ポリシー

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "secretsmanager:GetSecretValue",
      "secretsmanager:CreateSecret",
      "secretsmanager:PutSecretValue",
      "secretsmanager:DescribeSecret"
    ],
    "Resource": "arn:aws:secretsmanager:ap-northeast-1:*:secret:crypto/ecdsa/*"
  }]
}
```

---

## .NET 10 主要適用機能

| 機能 | 変更前（.NET 8） | 変更後（.NET 10） |
|------|----------------|-----------------|
| クラスコンストラクタ | 通常のコンストラクタ | **Primary Constructor** |
| スレッド同期 | `SemaphoreSlim` | **`System.Threading.Lock`** |
| データモデル | `class` + setter | **`record` + `required init`** |
| 署名結果 | 通常クラス | **Positional record** |
| 時刻型 | `DateTime` | **`DateTimeOffset`** |
| PEMインポート | 手動Base64パース | **`ImportFromPem()`** |
| コレクション初期化 | `new List<>()` | **コレクション式 `[..]`** |
| オプション管理 | 手動設定 | **`IOptions<T>` パターン** |
| リソース解放 | `IDisposable` | **`IAsyncDisposable`** |

---

## プロジェクト構造

```
CryptoCommon.sln
├── CryptoCommon/
│   ├── Models/
│   │   └── EcdsaModels.cs                  # データモデル（record）
│   ├── Interfaces/
│   │   └── ICryptoInterfaces.cs            # サービスインターフェース
│   ├── Services/
│   │   ├── AwsEcdsaKeyStore.cs             # AWS Secrets Manager 鍵ストア
│   │   └── EcdsaCryptoService.cs           # ECDSA 署名・検証サービス
│   ├── Extensions/
│   │   └── ServiceCollectionExtensions.cs  # DI登録拡張メソッド
│   └── CryptoCommon.csproj
└── CryptoCommon.Tests/
    ├── EcdsaCryptoServiceTests.cs          # 単体テスト（xUnit + Moq）
    └── CryptoCommon.Tests.csproj
```

---

## テスト実行

```bash
dotnet test --verbosity normal

# カバレッジ付きで実行
dotnet test --collect:"XPlat Code Coverage"
```

---

## NuGet 公開ガイド

### STEP 1 — nuget.org アカウントと API キーの取得

1. [nuget.org](https://nuget.org) にアクセス → Microsoft アカウントでログイン
2. 右上の **アカウント名** → **API Keys** をクリック
3. **Create** をクリックして設定:
   - Key Name: `CryptoCommon-publish`
   - Glob Pattern: `CryptoCommon.Ecdsa*`
   - 権限: **Push** にチェック
4. **Create** → キーを安全な場所に保管 ⚠️（一度しか表示されません）

### STEP 2 — パッケージのビルド

```bash
dotnet pack CryptoCommon/CryptoCommon.csproj -c Release

# 生成ファイル:
# CryptoCommon/bin/Release/CryptoCommon.Ecdsa.2.0.0.nupkg
# CryptoCommon/bin/Release/CryptoCommon.Ecdsa.2.0.0.snupkg  （シンボル）
```

### STEP 3 — nuget.org へデプロイ

```bash
dotnet nuget push CryptoCommon/bin/Release/CryptoCommon.Ecdsa.2.0.0.nupkg \
  --api-key YOUR_API_KEY \
  --source https://api.nuget.org/v3/index.json

dotnet nuget push CryptoCommon/bin/Release/CryptoCommon.Ecdsa.2.0.0.snupkg \
  --api-key YOUR_API_KEY \
  --source https://api.nuget.org/v3/index.json
```

### STEP 4 — GitHub Actions による自動デプロイ

`.github/workflows/nuget-publish.yml` を追加すると、タグのプッシュだけで自動デプロイできます。

```yaml
name: NuGetへ公開

on:
  push:
    tags: [ 'v*.*.*' ]   # v2.0.0 形式のタグプッシュ時に自動実行

jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0   # SourceLink のために全履歴が必要

      - name: .NET 10 セットアップ
        uses: actions/setup-dotnet@v4
        with:
          dotnet-version: '10.x'

      - name: 依存関係の復元
        run: dotnet restore

      - name: ビルド
        run: dotnet build --no-restore -c Release

      - name: テスト
        run: dotnet test --no-build -c Release

      - name: パッケージ作成
        run: dotnet pack CryptoCommon/CryptoCommon.csproj --no-build -c Release

      - name: NuGet へプッシュ
        run: |
          dotnet nuget push CryptoCommon/bin/Release/*.nupkg \
            --api-key ${{ secrets.NUGET_API_KEY }} \
            --source https://api.nuget.org/v3/index.json \
            --skip-duplicate
```

**GitHub Secrets の設定:**

1. GitHub リポジトリ → **Settings** → **Secrets and variables** → **Actions**
2. **New repository secret**: Name = `NUGET_API_KEY`、Value = STEP 1 で取得した API キー

**デプロイ手順:**

```bash
git tag v2.0.0
git push origin v2.0.0   # → GitHub Actions が自動でビルド・テスト・デプロイ
```

### バージョン管理（Semantic Versioning）

| 変更の種類 | 上げるバージョン | 例 |
|-----------|----------------|-----|
| バグ修正 | Patch | `2.0.0` → `2.0.1` |
| 後方互換の機能追加 | Minor | `2.0.0` → `2.1.0` |
| 後方非互換の変更 | Major | `2.0.0` → `3.0.0` |

---

## 依存パッケージ

| パッケージ | バージョン | 用途 |
|-----------|-----------|------|
| `AWSSDK.SecretsManager` | 3.7.* | AWS Secrets Manager 連携 |
| `Microsoft.Extensions.Logging.Abstractions` | 10.0.* | ロギング抽象化 |
| `Microsoft.Extensions.Options` | 10.0.* | IOptions 設定パターン |
| `Microsoft.Extensions.DependencyInjection.Abstractions` | 10.0.* | DI 抽象化 |

> ECDSA P-256 暗号化は .NET 10 組み込みの `System.Security.Cryptography` を使用するため、別途暗号化ライブラリは不要です。

---

## ライセンス

MIT License — 詳細は [LICENSE](LICENSE) ファイルを参照してください。
