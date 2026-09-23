import unittest

from decaytoken import (
    AttenuationError, ExpiredError, Issuer, MAX_SEGMENTS, NotYetValidError,
    ReplayError, RevocationList, RevokedError, SignatureError, SizeLimitError,
    StructureError, Token, UsageStore, Verifier,
)
from decaytoken.core import _b64d, _canonical, _hmac_hex

KEY = b"test-secret-key"
NOW = 1_700_000_000


def make_issuer():
    return Issuer(KEY, "auth.svc")


def make_token(**kw):
    args = dict(subject="alice", perms=["read", "write"],
                res="svc://db/*", ttl=3600, now=NOW)
    args.update(kw)
    return make_issuer().mint(**args)


def make_verifier(**kw):
    args = dict(leeway=60)
    args.update(kw)
    return Verifier(KEY, "auth.svc", **args)


def forge_append(token, caveats):
    """模拟恶意持有人：自己算 HMAC 追加一段（链签名合法但内容放权）。"""
    sig = _hmac_hex(_b64d(token.signature), _canonical(caveats))
    return Token(dict(token.header),
                 token.segments + [{"caveats": caveats, "sig": sig}],
                 token.root_sig)


class TestRoundTrip(unittest.TestCase):
    def test_mint_verify(self):
        token = make_token()
        claims = make_verifier().verify(token, now=NOW + 10)
        self.assertEqual(claims["sub"], "alice")
        self.assertEqual(claims["perms"], ["read", "write"])
        self.assertEqual(claims["res"], "svc://db/*")

    def test_serialize_parse_roundtrip(self):
        token = make_token().attenuate(perms=["read"], res="svc://db/t1")
        text = token.serialize()
        parsed = Token.parse(text)
        claims = make_verifier().verify(parsed, now=NOW)
        self.assertEqual(claims["perms"], ["read"])
        self.assertEqual(claims["res"], "svc://db/t1")

    def test_verify_accepts_serialized_string(self):
        token = make_token()
        claims = make_verifier().verify(token.serialize(), now=NOW)
        self.assertEqual(claims["jti"], token.header["jti"])

    def test_attenuate_chain_offline(self):
        # 逐段衰减：缩权限、缩范围、缩短有效期、限制次数、一次性
        t = make_token()
        t1 = t.attenuate(perms=["read"])
        t2 = t1.attenuate(res="svc://db/table1", exp=NOW + 600)
        t3 = t2.attenuate(max_uses=5, use_once=True)
        claims = make_verifier().verify(t3, now=NOW)
        self.assertEqual(claims["perms"], ["read"])
        self.assertEqual(claims["res"], "svc://db/table1")
        self.assertEqual(claims["exp"], NOW + 600)
        self.assertTrue(claims["use_once"])


class TestTampering(unittest.TestCase):
    def test_tamper_header_locates_root(self):
        token = make_token()
        token.header["perms"] = ["read", "write", "admin"]
        with self.assertRaises(SignatureError) as ctx:
            make_verifier().verify(token, now=NOW)
        self.assertEqual(ctx.exception.segment, 0)

    def test_tamper_segment_locates_position(self):
        token = make_token().attenuate(perms=["read"]).attenuate(
            res="svc://db/t1").attenuate(exp=NOW + 300)
        token.segments[1]["caveats"]["res"] = "svc://db/*"  # 改第 2 段
        with self.assertRaises(SignatureError) as ctx:
            make_verifier().verify(token, now=NOW)
        self.assertEqual(ctx.exception.segment, 2)

    def test_tamper_last_segment(self):
        token = make_token().attenuate(perms=["read"]).attenuate(exp=NOW + 300)
        token.segments[-1]["caveats"]["exp"] = NOW + 300  # 内容不变但换掉签名
        token.segments[-1]["sig"] = token.segments[0]["sig"]
        with self.assertRaises(SignatureError) as ctx:
            make_verifier().verify(token, now=NOW)
        self.assertEqual(ctx.exception.segment, 2)

    def test_wrong_key_rejected(self):
        token = make_token()
        with self.assertRaises(SignatureError) as ctx:
            Verifier(b"other-key").verify(token, now=NOW)
        self.assertEqual(ctx.exception.segment, 0)

    def test_garbage_token_rejected(self):
        for bad in ("not-a-token", "", "!!!", "a" * 100):
            with self.assertRaises((StructureError, SizeLimitError)):
                make_verifier().verify(bad, now=NOW)

    def test_missing_header_field_rejected(self):
        token = make_token()
        del token.header["sub"]
        with self.assertRaises(StructureError):
            Token.parse(token.serialize())


class TestEscalation(unittest.TestCase):
    """放权必须在两处被拒：attenuate 本地预检 + verify 服务端复查。"""

    def check_escalation(self, caveats, claim):
        token = make_token()
        # 1) 正常途径被本地拒绝
        with self.assertRaises(AttenuationError) as ctx:
            token.attenuate(**caveats)
        self.assertEqual(ctx.exception.segment, 1)
        self.assertEqual(ctx.exception.claim, claim)
        # 2) 恶意持有人伪造合法 HMAC 链，仍被验证方拒绝并定位
        forged = forge_append(token, caveats)
        with self.assertRaises(AttenuationError) as ctx2:
            make_verifier().verify(forged, now=NOW)
        self.assertEqual(ctx2.exception.segment, 1)
        self.assertEqual(ctx2.exception.claim, claim)

    def test_escalate_perms(self):
        self.check_escalation({"perms": ["read", "write", "admin"]}, "perms")

    def test_escalate_exp(self):
        self.check_escalation({"exp": NOW + 99999}, "exp")

    def test_escalate_nbf_earlier(self):
        token = make_token(nbf=NOW + 100)
        with self.assertRaises(AttenuationError) as ctx:
            token.attenuate(nbf=NOW)
        self.assertEqual(ctx.exception.claim, "nbf")

    def test_escalate_res(self):
        self.check_escalation({"res": "svc://*"}, "res")

    def test_escalate_max_uses(self):
        token = make_token(max_uses=3)
        with self.assertRaises(AttenuationError) as ctx:
            token.attenuate(max_uses=10)
        self.assertEqual(ctx.exception.claim, "max_uses")

    def test_escalate_use_once_removal(self):
        token = make_token().attenuate(use_once=True)
        with self.assertRaises(AttenuationError) as ctx:
            token.attenuate(use_once=False)
        self.assertEqual(ctx.exception.claim, "use_once")

    def test_unknown_caveat_rejected(self):
        self.check_escalation({"is_admin": True}, "is_admin")

    def test_escalation_position_in_middle_segment(self):
        token = make_token().attenuate(perms=["read"])
        forged = forge_append(token, {"perms": ["read", "admin"]})
        with self.assertRaises(AttenuationError) as ctx:
            make_verifier().verify(forged, now=NOW)
        self.assertEqual(ctx.exception.segment, 2)
        self.assertEqual(ctx.exception.claim, "perms")


class TestExpiryAndClockSkew(unittest.TestCase):
    def test_expired_rejected(self):
        token = make_token()
        with self.assertRaises(ExpiredError):
            make_verifier().verify(token, now=NOW + 3600 + 61)

    def test_clock_skew_within_leeway_accepted(self):
        token = make_token()
        # 验证方时钟快 30 秒（在 60 秒宽容度内），不应误判过期
        claims = make_verifier().verify(token, now=NOW + 3600 + 30)
        self.assertEqual(claims["sub"], "alice")

    def test_not_yet_valid(self):
        token = make_token(nbf=NOW + 1000)
        with self.assertRaises(NotYetValidError):
            make_verifier().verify(token, now=NOW)

    def test_nbf_within_leeway_accepted(self):
        token = make_token(nbf=NOW + 30)
        claims = make_verifier().verify(token, now=NOW)
        self.assertEqual(claims["sub"], "alice")

    def test_attenuated_expiry_enforced(self):
        token = make_token().attenuate(exp=NOW + 100)
        with self.assertRaises(ExpiredError):
            make_verifier().verify(token, now=NOW + 100 + 61)


class TestRevocation(unittest.TestCase):
    def test_revoked_rejected(self):
        revocation = RevocationList()
        token = make_token()
        revocation.revoke(token.header["jti"], exp=token.header["exp"])
        with self.assertRaises(RevokedError):
            make_verifier(revocation=revocation).verify(token, now=NOW)

    def test_other_token_unaffected(self):
        revocation = RevocationList()
        t1, t2 = make_token(), make_token()
        revocation.revoke(t1.header["jti"])
        claims = make_verifier(revocation=revocation).verify(t2, now=NOW)
        self.assertEqual(claims["jti"], t2.header["jti"])

    def test_revocation_cleanup(self):
        revocation = RevocationList()
        revocation.revoke("a", exp=NOW + 10)
        revocation.revoke("b", exp=NOW + 10000)
        revocation.cleanup(now=NOW + 20)
        self.assertFalse(revocation.is_revoked("a"))
        self.assertTrue(revocation.is_revoked("b"))


class TestReplay(unittest.TestCase):
    def test_use_once_replay_rejected(self):
        usage = UsageStore()
        verifier = make_verifier(usage=usage)
        token = make_token().attenuate(use_once=True)
        verifier.verify(token, now=NOW)
        with self.assertRaises(ReplayError):
            verifier.verify(token, now=NOW)

    def test_max_uses_counted(self):
        usage = UsageStore()
        verifier = make_verifier(usage=usage)
        token = make_token(max_uses=2)
        verifier.verify(token, now=NOW)
        verifier.verify(token, now=NOW)
        with self.assertRaises(ReplayError):
            verifier.verify(token, now=NOW)

    def test_unlimited_by_default(self):
        verifier = make_verifier()
        token = make_token()
        for _ in range(5):
            verifier.verify(token, now=NOW)

    def test_attenuated_copy_has_own_budget(self):
        usage = UsageStore()
        verifier = make_verifier(usage=usage)
        token = make_token(max_uses=1)
        narrowed = token.attenuate(perms=["read"])
        verifier.verify(token, now=NOW)
        verifier.verify(narrowed, now=NOW)  # 指纹不同，互不占额度
        with self.assertRaises(ReplayError):
            verifier.verify(token, now=NOW)

    def test_usage_cleanup(self):
        usage = UsageStore()
        verifier = make_verifier(usage=usage)
        token = make_token(max_uses=1)
        verifier.verify(token, now=NOW)
        usage.cleanup(now=NOW + 3600 + 1)
        self.assertEqual(usage._entries, {})


class TestLimits(unittest.TestCase):
    def test_chain_length_limit(self):
        token = make_token()
        for _ in range(MAX_SEGMENTS):
            token = token.attenuate(exp=token.effective_claims()["exp"])
        with self.assertRaises(SizeLimitError):
            token.attenuate(perms=["read"])

    def test_parse_rejects_overlong_chain(self):
        token = make_token()
        token.segments = [{"caveats": {}, "sig": "x"}] * (MAX_SEGMENTS + 1)
        with self.assertRaises(SizeLimitError):
            Token.parse(token.serialize())

    def test_parse_rejects_oversized_blob(self):
        from decaytoken import MAX_TOKEN_BYTES
        with self.assertRaises(SizeLimitError):
            Token.parse("a" * (MAX_TOKEN_BYTES + 1))


class TestOfflineConsistency(unittest.TestCase):
    def test_two_verifiers_same_key_agree(self):
        # 两个互不通联的验证方，凭同一密钥对同一令牌结论一致
        token = make_token().attenuate(perms=["read"])
        text = token.serialize()
        c1 = Verifier(KEY).verify(text, now=NOW)
        c2 = Verifier(KEY).verify(text, now=NOW)
        self.assertEqual(c1, c2)

    def test_wrong_issuer_rejected(self):
        token = Issuer(KEY, "other.svc").mint(
            "bob", ["read"], "svc://x", 100, now=NOW)
        with self.assertRaises(StructureError):
            make_verifier().verify(token, now=NOW)


if __name__ == "__main__":
    unittest.main()
