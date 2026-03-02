# CryptoCommon - ECDSA 암호화 공통모듈 (.NET 10)

AWS Secrets Manager와 연동된 ECDSA(P-256) 서명/검증 NuGet 패키지

---

## 프로젝트 구조

```
CryptoCommon.sln
├── CryptoCommon/                          # 메인 라이브러리
│   ├── Models/
│   │   └── EcdsaModels.cs                 # 데이터 모델 (record)
│   ├── Interfaces/
│   │   └── ICryptoInterfaces.cs           # 서비스 인터페이스
│   ├── Services/
│   │   ├── AwsEcdsaKeyStore.cs            # AWS Secrets Manager 키 저장소
│   │   └── EcdsaCryptoService.cs          # ECDSA 서명/검증 서비스
│   ├── Extensions/
│   │   └── ServiceCollectionExtensions.cs # DI 등록 확장 메서드
│   └── CryptoCommon.csproj
└── CryptoCommon.Tests/                    # 단위 테스트 (xUnit + Moq)
    ├── EcdsaCryptoServiceTests.cs
    └── CryptoCommon.Tests.csproj
```

---

## 아키텍처

```
┌──────────────────────────────────────────────────┐
│                   애플리케이션                     │
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
                    │  crypto/ecdsa/active-key    │ ← 현재 활성 키
                    │  crypto/ecdsa/keys/{keyId}  │ ← 키 이력
                    └─────────────────────────────┘
```

---

## .NET 10 주요 적용 기능

| 기능 | 설명 |
|------|------|
| **Primary Constructor** | 클래스 선언부에서 의존성 주입 |
| **System.Threading.Lock** | `SemaphoreSlim` 대체, `EnterScope()` IDisposable 패턴 |
| **record + required init** | 불변 데이터 모델, 컴파일 타임 초기화 강제 |
| **Positional record** | `EcdsaSignatureResult` 간결한 선언 |
| **DateTimeOffset** | `DateTime` 대신 시간대 명시적 처리 |
| **ImportFromPem()** | PEM 헤더/푸터 자동 파싱 |
| **Collection expression `[..]`** | 컬렉션 초기화 간소화 |
| **IOptions\<T\> 패턴** | DI 친화적 옵션 관리 |
| **IAsyncDisposable** | 비동기 리소스 해제 |

---

## 빠른 시작

### 1. DI 등록

```csharp
// Program.cs
builder.Services.AddEcdsaCrypto(options =>
{
    options.ActiveKeySecretName = "myapp/ecdsa/active-key";
    options.KeySecretPrefix     = "myapp/ecdsa/keys";
    options.AwsRegion           = "ap-northeast-2";
    options.CacheTtl            = TimeSpan.FromMinutes(5);
});
```

### 2. 최초 키 생성

```csharp
await using var scope = app.Services.CreateAsyncScope();
var keyStore = scope.ServiceProvider.GetRequiredService<IEcdsaKeyStore>();
await keyStore.GenerateAndStoreKeyPairAsync();
```

### 3. 서명

```csharp
// Primary Constructor 방식 (DI)
public class PaymentService(IEcdsaCryptoService crypto)
{
    public async Task<string> SignPayloadAsync(string payload)
    {
        var result = await crypto.SignAsync(payload);
        return result.Signature; // Base64 서명값
    }
}
```

### 4. 검증

```csharp
// 활성 키로 검증
bool isValid = await crypto.VerifyAsync(dataBytes, signatureBase64);

// 특정 키 ID로 검증 (키 로테이션 이후 과거 서명도 검증 가능)
bool isValid = await crypto.VerifyAsync(new EcdsaVerifyRequest
{
    Data      = Encoding.UTF8.GetBytes(payload),
    Signature = signatureBase64,
    KeyId     = "A1B2C3D4"
});
```

### 5. 키 로테이션

```csharp
var newKey = await keyStore.RotateKeyPairAsync();
```

---

## 테스트 실행

```bash
dotnet test --verbosity normal
```

---

## AWS IAM 최소 권한

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
    "Resource": "arn:aws:secretsmanager:ap-northeast-2:*:secret:crypto/ecdsa/*"
  }]
}
```

---

## Secrets Manager 저장 형식

```json
{
  "KeyId": "A1B2C3D4",
  "PrivateKeyPem": "-----BEGIN EC PRIVATE KEY-----\n...\n-----END EC PRIVATE KEY-----",
  "PublicKeyPem":  "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
  "CreatedAt": "2025-01-01T00:00:00+00:00",
  "Curve": "P-256"
}
```

---

## 의존성

| 패키지 | 버전 | 용도 |
|--------|------|------|
| `AWSSDK.SecretsManager` | 3.7.* | AWS Secrets Manager 연동 |
| `Microsoft.Extensions.Logging.Abstractions` | 10.0.* | 로깅 추상화 |
| `Microsoft.Extensions.Options` | 10.0.* | IOptions 설정 패턴 |
| `Microsoft.Extensions.DependencyInjection.Abstractions` | 10.0.* | DI 추상화 |

> ECDSA P-256 암호화는 .NET 10 내장 `System.Security.Cryptography` 사용 — 별도 라이브러리 불필요
