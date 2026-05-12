# CryptoTrace — 信息安全密码算法接口化实现与可测验证平台

基于 **Python + Flask** 构建的密码算法平台，所有核心算法**从零实现**（不依赖第三方密码库），提供 RESTful JSON API 与浏览器可视化操作界面。

## 快速启动

```bash
# 安装依赖
pip install -r requirements.txt

# 启动服务
python app.py
```

默认访问：`http://127.0.0.1:5000/`

## 算法覆盖

| 类别 | 算法 | Trace 级别 | 参考标准 |
|---|---|---|---|
| 编码 | Base64 | L1 / L2 | RFC 4648 |
| 编码 | UTF-8 | L1 / L2 | RFC 3629 |
| 哈希 | SHA-256 | L1 + L2 | FIPS 180-4 |
| 哈希 | SHA-1 | L1 | FIPS 180-4 |
| 哈希 | SHA-3 (Keccak) | L1 | FIPS 202 |
| 哈希 | RIPEMD-160 | L1 | ISO/IEC 10118-3 |
| MAC | HMAC-SHA256 / HMAC-SHA1 | L1 | RFC 2104 / RFC 4231 |
| KDF | PBKDF2 | L1 | RFC 8018 |
| 对称加密 | AES-128 (ECB/CBC) | L1 + L2 | FIPS 197 |
| 对称加密 | SM4 (ECB/CBC) | L1 | GB/T 32907-2016 |
| 对称加密 | RC6-32/20/b (ECB/CBC) | L1 | RC6 Paper (1998) |
| 公钥密码 | RSA-1024 | L1 + L2 | PKCS#1 v1.5 (RFC 8017) |
| 签名 | RSA-SHA1 | L1 + L2 | PKCS#1 v1.5 |
| 椭圆曲线 | ECC-160 (secp160r1) | L1 + L2 | SEC 2 |
| 签名 | ECDSA | L1 + L2 | SEC 1 |

## 页面入口

| 页面 | URL | 说明 |
|---|---|---|
| 首页 | `/` | 平台介绍与快速导航 |
| 对称加密 | `/symmetric/` | AES / SM4 / RC6 |
| 哈希与派生 | `/hash/` | SHA-256 / SHA-1 / SHA-3 / RIPEMD-160 / HMAC / PBKDF2 |
| 编码转换 | `/encoding/` | Base64 / UTF-8 |
| 公钥与签名 | `/asymmetric/` | RSA / RSA-SHA1 / ECC / ECDSA |
| 自检验证 | `/selftest` | 一键运行全部算法测试向量 |
| 关于 | `/about` | 项目详情、架构说明 |

## API 端点

所有 API 使用 `POST` 方法，请求体为 JSON，返回统一格式：

```json
{
  "status_code": 0,
  "status_message": "OK",
  "result": { ... },
  "trace": { ... },
  "time_ms": 1.234
}
```

### 编码

| 端点 | 说明 |
|---|---|
| `/api/encoding/base64/encode` | Base64 编码 |
| `/api/encoding/base64/decode` | Base64 解码 |
| `/api/encoding/utf8/encode` | UTF-8 编码 |
| `/api/encoding/utf8/decode` | UTF-8 解码 |

### 哈希

| 端点 | 说明 |
|---|---|
| `/api/hash/digest` | 哈希摘要 (algorithm: SHA256/SHA1/SHA3/RIPEMD160) |

### MAC / KDF

| 端点 | 说明 |
|---|---|
| `/api/hmac/compute` | HMAC 计算 (algorithm: HmacSHA256/HmacSHA1) |
| `/api/kdf/pbkdf2` | PBKDF2 密钥派生 |

### 对称加密

| 端点 | 说明 |
|---|---|
| `/api/symmetric/aes/encrypt` | AES-128 加密 |
| `/api/symmetric/aes/decrypt` | AES-128 解密 |
| `/api/symmetric/sm4/encrypt` | SM4 加密 |
| `/api/symmetric/sm4/decrypt` | SM4 解密 |
| `/api/symmetric/rc6/encrypt` | RC6 加密 |
| `/api/symmetric/rc6/decrypt` | RC6 解密 |

### 公钥密码

| 端点 | 说明 |
|---|---|
| `/api/asymmetric/rsa/keygen` | RSA 密钥生成 |
| `/api/asymmetric/rsa/sign` | RSA 签名 |
| `/api/asymmetric/rsa/verify` | RSA 验签 |
| `/api/asymmetric/rsa-sha1/sign` | RSA-SHA1 签名 |
| `/api/asymmetric/rsa-sha1/verify` | RSA-SHA1 验签 |
| `/api/asymmetric/ecc/keygen` | ECC 密钥生成 |
| `/api/asymmetric/ecdsa/sign` | ECDSA 签名 |
| `/api/asymmetric/ecdsa/verify` | ECDSA 验签 |

### 自检

| 端点 | 说明 |
|---|---|
| `/api/selftest/run` | 运行全部算法测试向量 |

### API 调用示例

```bash
# SHA-256 摘要
curl -X POST http://127.0.0.1:5000/api/hash/digest \
  -H "Content-Type: application/json" \
  -d '{"algorithm":"SHA256","data":"616263","encoding":"hex","output":"hex"}'

# AES 加密
curl -X POST http://127.0.0.1:5000/api/symmetric/aes/encrypt \
  -H "Content-Type: application/json" \
  -d '{"data":"6bc1bee22e409f96e93d7e117393172a","key":"2b7e151628aed2a6abf7158809cf4f3c","mode":"ECB","padding":"none","output":"hex"}'

# RSA 密钥生成
curl -X POST http://127.0.0.1:5000/api/asymmetric/rsa/keygen \
  -H "Content-Type: application/json" \
  -d '{"bits":1024}'
```

更多示例见 `scripts/api_demo.py` 和 `scripts/api_demo.sh`。

## 状态码

| 范围 | 含义 | 示例 |
|---|---|---|
| 0 | 成功 | OK |
| 1xxx | 参数错误 | 1002 Missing field, 1005 Unsupported algorithm, 1007 Invalid key length |
| 2xxx | 算法执行错误 | 2001 Decrypt failed, 2004 RSA key invalid, 2009 Mod inverse not exist |
| 3xxx | 编码解码错误 | 3001 Hex decode error, 3002 Base64 decode error |
| 9xxx | 系统错误 | 9001 Internal error, 9002 Not implemented |

## 自检验证

运行自检可验证所有算法的正确性：

```bash
# 通过 API
curl -X POST http://127.0.0.1:5000/api/selftest/run

# 或访问浏览器 /selftest 页面
```

当前结果：**24 PASS, 0 FAIL, 0 not_implemented**

## 测试

```bash
# 运行 pytest 单元测试
python -m pytest utils/tests/cases/ -v

# 运行自检引擎
python -c "from utils.tests.selftest import run_selftest; print(run_selftest()['result']['summary'])"
```

## 项目结构

```
crypto_trace_api/
├── app.py                    # 入口
├── config.py                 # Flask 配置
├── requirements.txt
├── utils/                    # 算法层（从零实现）
│   ├── common/               # 公共模块（encoding/validation/trace/timing）
│   ├── encoding/             # Base64 / UTF-8
│   ├── hash/                 # SHA-256 / SHA-1 / SHA-3 / RIPEMD-160
│   ├── mac_kdf/              # HMAC / PBKDF2
│   ├── symmetric/            # AES-128 / SM4 / RC6
│   ├── asymmetric/           # RSA / RSA-SHA1 / ECC / ECDSA
│   └── tests/                # 自检引擎 + 测试向量 + pytest 用例
├── webapp/                   # Web 层
│   ├── views/                # 页面路由 + API 蓝图
│   ├── templates/            # Jinja2 模板（三级继承）
│   └── static/css/           # 样式
└── scripts/                  # API 调用示例脚本
```

## Trace 追踪

支持两级 Trace 追踪，使算法执行过程透明可审计：

- **Level 1**：所有算法通用摘要（算法名、操作、输入输出摘要、参数、耗时）
- **Level 2**：关键算法详细中间步骤
  - AES：轮密钥摘要、每轮 state 采样
  - SHA-256：消息调度 W[t] 摘要、压缩函数寄存器采样
  - RSA：p/q 位数、e/d 生成摘要、签名关键步骤
  - ECDSA：k 生成摘要、点运算摘要、(r,s) 值

在 API 请求中设置 `trace: true, trace_level: 2` 即可开启。
