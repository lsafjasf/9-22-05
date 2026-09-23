"""可衰减能力令牌（decaytoken）。

macaroon 风格的 HMAC 链式令牌：
- 签发方持有密钥，签出根令牌；
- 持有人无需联系签发方，即可用当前链尾签名作为 HMAC 密钥追加衰减段；
- 验证方用同一密钥离线重放整条链，逐段比对签名，可定位被篡改的段。

仅使用 Python 标准库。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time

MAX_SEGMENTS = 16          # 衰减链最大段数
MAX_TOKEN_BYTES = 8192     # 序列化后最大字节数
DEFAULT_LEEWAY_SECONDS = 60  # 默认时钟宽容度

ALLOWED_CAVEATS = ("exp", "nbf", "perms", "res", "max_uses", "use_once")
_EFFECTIVE_FIELDS = ("exp", "nbf", "perms", "res", "max_uses", "use_once")
_HEADER_FIELDS = (
    "v", "iss", "sub", "jti", "iat", "nbf", "exp",
    "perms", "res", "max_uses", "use_once",
)


# ---------------------------------------------------------------- 错误类型

class TokenError(Exception):
    """所有令牌错误的基类。"""


class StructureError(TokenError):
    """令牌结构不合法（编码、字段、类型、大小等）。"""


class SizeLimitError(TokenError):
    """链长度或总体积超限。"""


class SignatureError(TokenError):
    """签名链校验失败。segment=0 表示根签名（头部），>=1 表示第几段衰减。"""

    def __init__(self, segment: int):
        self.segment = segment
        where = "根签名/头部" if segment == 0 else f"第 {segment} 段衰减"
        super().__init__(f"签名校验失败，篡改位置：{where}")


class AttenuationError(TokenError):
    """衰减试图放权或包含未知声明。segment 为 1 基段号，claim 为违规声明名。"""

    def __init__(self, segment: int, claim: str, reason: str):
        self.segment = segment
        self.claim = claim
        super().__init__(f"非法衰减：第 {segment} 段声明 {claim!r}：{reason}")


class ExpiredError(TokenError):
    pass


class NotYetValidError(TokenError):
    pass


class RevokedError(TokenError):
    pass


class ReplayError(TokenError):
    pass


# ---------------------------------------------------------------- 工具函数

def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64d(text: str) -> bytes:
    if not isinstance(text, str):
        raise StructureError("签名字段必须是字符串")
    pad = "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode(text + pad)
    except Exception as exc:
        raise StructureError(f"base64 解码失败: {exc}") from exc


def _canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _hmac_hex(key: bytes, msg: bytes) -> str:
    return _b64e(hmac.new(key, msg, hashlib.sha256).digest())


def _scope_covers(parent: str, child: str) -> bool:
    """parent 资源范围是否覆盖 child。支持末尾 '*' 前缀通配。"""
    if parent == child:
        return True
    if parent.endswith("*"):
        return child.startswith(parent[:-1])
    return False


def _require_int(value, segment: int, claim: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise AttenuationError(segment, claim, "必须是整数")
    return value


def _apply_caveats(eff: dict, caveats: dict, segment: int) -> None:
    """把一段衰减条件折叠进有效声明 eff；任何放权尝试都抛 AttenuationError。"""
    if not isinstance(caveats, dict):
        raise AttenuationError(segment, "<segment>", "衰减段必须是对象")
    for claim, value in caveats.items():
        if claim not in ALLOWED_CAVEATS:
            raise AttenuationError(segment, claim, "未知声明")

        if claim == "exp":
            value = _require_int(value, segment, claim)
            if value > eff["exp"]:
                raise AttenuationError(segment, claim, "有效期只能缩短")
            eff["exp"] = value

        elif claim == "nbf":
            value = _require_int(value, segment, claim)
            if value < eff["nbf"]:
                raise AttenuationError(segment, claim, "生效时间只能推迟")
            eff["nbf"] = value

        elif claim == "perms":
            if (not isinstance(value, list)
                    or any(not isinstance(p, str) for p in value)):
                raise AttenuationError(segment, claim, "权限必须是字符串数组")
            if not set(value) <= set(eff["perms"]):
                raise AttenuationError(segment, claim, "权限集合只能缩小")
            eff["perms"] = sorted(set(value))

        elif claim == "res":
            if not isinstance(value, str):
                raise AttenuationError(segment, claim, "资源范围必须是字符串")
            if not _scope_covers(eff["res"], value):
                raise AttenuationError(segment, claim, "资源范围只能缩小")
            eff["res"] = value

        elif claim == "max_uses":
            value = _require_int(value, segment, claim)
            if value < 1:
                raise AttenuationError(segment, claim, "max_uses 必须 >= 1")
            if eff["max_uses"] is not None and value > eff["max_uses"]:
                raise AttenuationError(segment, claim, "使用次数上限只能降低")
            eff["max_uses"] = value

        elif claim == "use_once":
            if value is not True:
                raise AttenuationError(segment, claim, "use_once 只能被设置为 true")
            eff["use_once"] = True


# ---------------------------------------------------------------- 令牌

class Token:
    """一个令牌 = 头部 + 衰减段列表 + 根签名。每段自带链式签名。"""

    def __init__(self, header: dict, segments: list, root_sig: str):
        self.header = header
        self.segments = segments  # [{"caveats": {...}, "sig": "..."}]
        self.root_sig = root_sig

    # -- 链尾签名：无衰减段时即根签名
    @property
    def signature(self) -> str:
        return self.segments[-1]["sig"] if self.segments else self.root_sig

    # -- 有效声明：头部声明经所有衰减段折叠后的结果
    def effective_claims(self) -> dict:
        eff = {k: self.header[k] for k in _EFFECTIVE_FIELDS}
        for index, seg in enumerate(self.segments, start=1):
            _apply_caveats(eff, seg["caveats"], index)
        eff.update({k: self.header[k] for k in ("iss", "sub", "jti", "iat")})
        return eff

    def attenuate(self, **caveats) -> "Token":
        """持有人离线追加一段衰减。只允许收缩，否则抛 AttenuationError。"""
        if len(self.segments) >= MAX_SEGMENTS:
            raise SizeLimitError(
                f"衰减链已达上限 {MAX_SEGMENTS} 段，请向签发方申请重新签发以压缩链")
        eff = self.effective_claims()
        _apply_caveats(eff, caveats, len(self.segments) + 1)  # 本地预检
        new_sig = _hmac_hex(_b64d(self.signature), _canonical(caveats))
        token = Token(dict(self.header),
                      self.segments + [{"caveats": dict(caveats), "sig": new_sig}],
                      self.root_sig)
        if len(token.serialize()) > MAX_TOKEN_BYTES:
            raise SizeLimitError(
                f"令牌体积超过上限 {MAX_TOKEN_BYTES} 字节，请重新签发以压缩链")
        return token

    def serialize(self) -> str:
        return _b64e(_canonical({
            "h": self.header, "s": self.segments, "r": self.root_sig}))

    @classmethod
    def parse(cls, data) -> "Token":
        if isinstance(data, bytes):
            try:
                data = data.decode("ascii")
            except UnicodeDecodeError as exc:
                raise StructureError("令牌必须是 ASCII/base64url") from exc
        if not isinstance(data, str):
            raise StructureError("令牌必须是字符串或字节")
        if len(data) > MAX_TOKEN_BYTES:
            raise SizeLimitError(f"令牌体积超过上限 {MAX_TOKEN_BYTES} 字节")
        try:
            obj = json.loads(_b64d(data))
        except (StructureError, ValueError) as exc:
            raise StructureError(f"令牌无法解析: {exc}") from exc
        if not isinstance(obj, dict) or set(obj) != {"h", "s", "r"}:
            raise StructureError("令牌顶层结构不完整")
        header, segments, root_sig = obj["h"], obj["s"], obj["r"]
        if not isinstance(header, dict) or set(header) != set(_HEADER_FIELDS):
            raise StructureError("头部字段缺失或多余")
        if header["v"] != 1:
            raise StructureError("不支持的版本")
        for field in ("iss", "sub", "jti", "res"):
            if not isinstance(header[field], str):
                raise StructureError(f"头部字段 {field} 必须是字符串")
        for field in ("iat", "nbf", "exp"):
            if isinstance(header[field], bool) or not isinstance(header[field], int):
                raise StructureError(f"头部字段 {field} 必须是整数")
        if (not isinstance(header["perms"], list)
                or any(not isinstance(p, str) for p in header["perms"])):
            raise StructureError("头部 perms 必须是字符串数组")
        if header["max_uses"] is not None and (
                isinstance(header["max_uses"], bool)
                or not isinstance(header["max_uses"], int)
                or header["max_uses"] < 1):
            raise StructureError("头部 max_uses 必须是 >=1 的整数或 null")
        if header["use_once"] is not False:
            raise StructureError("头部 use_once 必须为 false（只能经衰减开启）")
        if not isinstance(segments, list):
            raise StructureError("衰减链必须是数组")
        if len(segments) > MAX_SEGMENTS:
            raise SizeLimitError(f"衰减链超过上限 {MAX_SEGMENTS} 段")
        for seg in segments:
            if not isinstance(seg, dict) or set(seg) != {"caveats", "sig"}:
                raise StructureError("衰减段结构不完整")
            _b64d(seg["sig"])  # 校验编码
        _b64d(root_sig)
        return cls(header, segments, root_sig)

    def fingerprint(self) -> str:
        """整枚令牌的稳定指纹，用于一次性使用 / 计数标记。"""
        return hashlib.sha256(_canonical(
            {"h": self.header, "s": self.segments, "r": self.root_sig}
        )).hexdigest()


# ---------------------------------------------------------------- 签发方

class Issuer:
    def __init__(self, key, issuer_id: str):
        self.key = key.encode("utf-8") if isinstance(key, str) else bytes(key)
        self.issuer_id = issuer_id

    def mint(self, subject: str, perms, res: str, ttl: int, *,
             nbf: int = None, max_uses: int = None,
             jti: str = None, now: float = None) -> Token:
        now = int(time.time() if now is None else now)
        header = {
            "v": 1,
            "iss": self.issuer_id,
            "sub": subject,
            "jti": jti or secrets.token_hex(16),
            "iat": now,
            "nbf": int(now if nbf is None else nbf),
            "exp": now + int(ttl),
            "perms": sorted(set(perms)),
            "res": res,
            "max_uses": max_uses,
            "use_once": False,
        }
        root_sig = _hmac_hex(self.key, _canonical(header))
        return Token(header, [], root_sig)


# ---------------------------------------------------------------- 验证方存储

class RevocationList:
    """撤销列表：jti -> 令牌过期时间（用于自动清理）。"""

    def __init__(self):
        self._entries = {}

    def revoke(self, jti: str, exp: int = None) -> None:
        self._entries[jti] = exp

    def is_revoked(self, jti: str) -> bool:
        return jti in self._entries

    def cleanup(self, now: float = None) -> None:
        now = time.time() if now is None else now
        self._entries = {j: e for j, e in self._entries.items()
                         if e is None or e > now}


class UsageStore:
    """一次性/计次使用标记：fingerprint -> [已用次数, 过期时间]。"""

    def __init__(self):
        self._entries = {}

    def check_and_mark(self, fingerprint: str, max_uses: int, exp: int) -> bool:
        count, _ = self._entries.get(fingerprint, (0, exp))
        if count >= max_uses:
            return False
        self._entries[fingerprint] = (count + 1, exp)
        return True

    def cleanup(self, now: float = None) -> None:
        now = time.time() if now is None else now
        self._entries = {f: v for f, v in self._entries.items() if v[1] > now}


# ---------------------------------------------------------------- 验证方

class Verifier:
    """离线验证方。只需共享密钥，无需网络。"""

    def __init__(self, key, issuer: str = None, *,
                 leeway: int = DEFAULT_LEEWAY_SECONDS,
                 revocation: RevocationList = None,
                 usage: UsageStore = None):
        self.key = key.encode("utf-8") if isinstance(key, str) else bytes(key)
        self.issuer = issuer
        self.leeway = int(leeway)
        self.revocation = revocation if revocation is not None else RevocationList()
        self.usage = usage if usage is not None else UsageStore()

    def verify(self, token, now: float = None) -> dict:
        """完整校验，返回有效声明；任何失败都抛 TokenError 子类。"""
        if isinstance(token, (str, bytes)):
            token = Token.parse(token)
        now = int(time.time() if now is None else now)

        # 1. 结构（parse 已查，这里对直接构造的 Token 再查一次链长）
        if len(token.segments) > MAX_SEGMENTS:
            raise SizeLimitError(f"衰减链超过上限 {MAX_SEGMENTS} 段")

        # 2. 签名链：先根签名，再逐段重放，定位第一个不匹配的段
        expected = _hmac_hex(self.key, _canonical(token.header))
        if not hmac.compare_digest(expected, token.root_sig):
            raise SignatureError(0)
        for index, seg in enumerate(token.segments, start=1):
            expected = _hmac_hex(_b64d(expected), _canonical(seg["caveats"]))
            if not hmac.compare_digest(expected, seg["sig"]):
                raise SignatureError(index)

        # 3. 衰减只允许收缩（持有人也能算 HMAC，必须服务端复查）
        eff = token.effective_claims()

        # 4. 签发方
        if self.issuer is not None and eff["iss"] != self.issuer:
            raise StructureError(f"签发方不符: {eff['iss']!r}")

        # 5. 有效期（含时钟宽容度，弱网/时钟略偏不会误判）
        if now > eff["exp"] + self.leeway:
            raise ExpiredError(f"令牌已过期: exp={eff['exp']} now={now}")
        if now < eff["nbf"] - self.leeway:
            raise NotYetValidError(f"令牌尚未生效: nbf={eff['nbf']} now={now}")

        # 6. 撤销列表
        if self.revocation.is_revoked(eff["jti"]):
            raise RevokedError(f"令牌已被撤销: jti={eff['jti']}")

        # 7. 一次性 / 计次使用
        max_uses = eff["max_uses"]
        if eff["use_once"]:
            max_uses = 1 if max_uses is None else min(max_uses, 1)
        if max_uses is not None:
            if not self.usage.check_and_mark(token.fingerprint(), max_uses, eff["exp"]):
                raise ReplayError(f"令牌使用次数已达上限 {max_uses}")

        return eff
