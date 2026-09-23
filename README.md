# decaytoken — 可衰减能力令牌

macaroon 风格的 HMAC 链式能力令牌，仅用 Python 3 标准库实现。
服务间用令牌传递授权：验证方**离线**校验，持有人**不接触签发方**即可把权限缩小后转交。

## 结构

```
decaytoken/
  __init__.py      # 公开 API 导出
  core.py          # 令牌、签发方、验证方、撤销列表、计次存储、错误类型
tests/
  test_decaytoken.py   # 36 个自测：篡改/放权/过期/撤销/重放/限额/离线一致性
```

### 令牌格式

```json
{
  "h": {                       // 头部（签发方写死，衰减不可改）
    "v": 1, "iss": "签发方", "sub": "主体", "jti": "唯一标识",
    "iat": 0, "nbf": 0, "exp": 0,
    "perms": ["read"], "res": "svc://db/*",
    "max_uses": null, "use_once": false
  },
  "s": [ {"caveats": {...}, "sig": "..."} ],   // 衰减链，逐段追加
  "r": "根签名"
}
```

签名链：`sig0 = HMAC(key, 头部)`，`sigN = HMAC(sig(N-1), 第N段衰减条件)`。
持有人知道当前链尾签名，因此无需签发方即可追加衰减段；
验证方用共享密钥重放整条链并逐段比对，**第一个不匹配的段号即篡改位置**
（`SignatureError.segment`，0 表示根签名/头部）。

### 衰减只允许收缩

允许的衰减声明（`ALLOWED_CAVEATS`）：`exp`（只能提前）、`nbf`（只能推迟）、
`perms`（只能取子集）、`res`（只能缩小，支持末尾 `*` 前缀通配）、
`max_uses`（只能降低）、`use_once`（只能置 true）。
任何放权尝试在 `attenuate()` 本地预检和 `verify()` 服务端复查两处都会被拒绝，
抛出 `AttenuationError(segment, claim)` 指明第几段、哪条声明。

## 威胁模型

**能防御**

- 伪造令牌：没有共享密钥无法构造合法根签名（HMAC-SHA256）。
- 篡改头部或任意衰减段：链式签名逐段失配，报错并定位段号。
- 持有人放权：持有人虽能算 HMAC 追加段，但验证方会折叠全链并强制
  "只收缩"不变量，放权段被精确指认。
- 过期/未生效令牌：有效期检查含可配置时钟宽容度（默认 60s），
  时钟略偏或弱网重试不会误判。
- 撤销：`RevocationList` 按 jti 撤销，条目随令牌过期自动清理。
- 重放：`use_once` / `max_uses` 由 `UsageStore` 按令牌指纹计数，
  超次抛 `ReplayError`；条目随 exp 自动清理。
- 无限增长：链长上限 16 段、序列化体积上限 8KB，超限时拒绝并提示
  重新签发（即压缩策略：由签发方把有效声明折叠成新根令牌）。

**不在范围内 / 部署注意**

- 令牌是持票凭证：被盗即在有效声明范围内被冒用，请配合短 TTL、
  缩小范围与 `use_once` 降低风险。
- 重放/计次存储是验证方本地状态：多实例部署需共享存储
  （如 Redis）才能全局一致；单实例或弱网分区下行为确定——
  本地已见的重放必拒，未同步的按本地计数判定。
- 密钥分发与轮换由部署方负责；撤销列表需带外同步给各验证方。
- 时钟宽容度是可用性与安全窗口的权衡，按环境调整 `leeway`。

## 运行

```bash
cd /home/administrator/gsb/uid5/B
python3 -m unittest discover -s tests -v   # 跑全部自测
```

## 用法示例

```python
from decaytoken import Issuer, Verifier, RevocationList

issuer = Issuer(b"shared-secret", "auth.svc")
token = issuer.mint("alice", ["read", "write"], "svc://db/*", ttl=3600)

# 持有人离线缩小权限后转交
narrowed = token.attenuate(perms=["read"], res="svc://db/t1",
                           exp=token.header["iat"] + 600, use_once=True)

verifier = Verifier(b"shared-secret", "auth.svc",
                    revocation=RevocationList())
claims = verifier.verify(narrowed.serialize())   # 通过则返回有效声明
```
