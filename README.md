# crypto_trace_api

一个基于 **Python + Flask** 的课程项目骨架，当前阶段重点是页面导航与模板结构可运行。

## 1. 创建虚拟环境

```bash
python -m venv .venv
source .venv/bin/activate
```

## 2. 安装依赖

```bash
pip install -r requirements.txt
```

## 3. 启动项目

```bash
python app.py
```

默认访问：`http://127.0.0.1:5000/`

## 4. 页面入口

- 首页：`/`
- 关于：`/about`
- 对称加密：`/symmetric`（默认跳转 `/symmetric/aes`）
- 哈希与派生：`/hash`（默认跳转 `/hash/sha256`）
- 编码：`/encoding`（默认跳转 `/encoding/base64`）
- 公钥与签名：`/asymmetric`（默认跳转 `/asymmetric/rsa`）
- 自检页面：`/selftest`

## 5. 说明

- `webapp/views/` 当前仅做页面渲染路由。
- `utils/` 当前为占位模块，后续再补算法实现。
