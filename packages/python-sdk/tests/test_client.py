import json
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

_SRC = str(Path(__file__).resolve().parents[1] / "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from tinplate import TinplateClient, TinplateError, __version__


class TestTinplateClient(unittest.TestCase):
    def test_version_matches_release(self) -> None:
        self.assertEqual(__version__, "1.1.8")
    def test_headers_rapidapi(self) -> None:
        client = TinplateClient(
            base_url="https://example.p.rapidapi.com/",
            rapidapi_key="rk_123",
            rapidapi_host="example.p.rapidapi.com",
            request_receipts=True,
        )
        self.assertEqual(client.base_url, "https://example.p.rapidapi.com")
        self.assertEqual(client.headers["X-RapidAPI-Key"], "rk_123")
        self.assertEqual(client.headers["X-RapidAPI-Host"], "example.p.rapidapi.com")
        self.assertEqual(client.headers["X-Tinplate-Receipt-Request"], "true")
        self.assertEqual(client.headers["User-Agent"], "tinplate-python/1.1.8")

    def test_headers_bearer_and_error(self) -> None:
        client = TinplateClient(api_key="tok_abc")
        self.assertEqual(client.headers["Authorization"], "Bearer tok_abc")
        err = TinplateError(401, "unauthorized", "Missing key")
        self.assertIn("401 unauthorized", str(err))

    def test_endpoint_wrappers_route_and_serialize(self) -> None:
        client = TinplateClient(api_key="tok_abc", request_receipts=True)
        fake_resp = MagicMock()
        fake_resp.read.return_value = json.dumps({"ok": True, "data": {"valid": True}}).encode("utf-8")
        fake_resp.__enter__.return_value = fake_resp

        with patch("urllib.request.urlopen", return_value=fake_resp) as mock_open:
            res = client.validate_iban(iban="DE89370400440532013000")
            self.assertTrue(res["ok"])
            req = mock_open.call_args[0][0]
            self.assertEqual(req.full_url, "https://api.tinplate.dev/v1/eu-vat-iban/iban?receipt=true")
            self.assertEqual(json.loads(req.data.decode("utf-8")), {"iban": "DE89370400440532013000"})

        for method in ("scan_secrets", "guard_llm_output", "ua_bot_parser", "guard_command_sql", "issue_action_receipt", "guard_llm_turn", "health", "list_presets"):
            self.assertTrue(callable(getattr(client, method)), f"Missing {method}")

    def test_https_enforcement_and_updated_signatures(self) -> None:
        with self.assertRaises(TinplateError) as ctx:
            TinplateClient(base_url="http://api.example.com", api_key="tok_secret")
        self.assertEqual(ctx.exception.code, "insecure_base_url")

        # localhost allowed without allow_insecure
        local_client = TinplateClient(base_url="http://localhost:8787", api_key="tok_secret")
        self.assertEqual(local_client.base_url, "http://localhost:8787")

        fake_resp = MagicMock()
        fake_resp.read.return_value = json.dumps({"ok": True, "data": {"verdict": "allow"}}).encode("utf-8")
        fake_resp.__enter__.return_value = fake_resp
        with patch("urllib.request.urlopen", return_value=fake_resp) as mock_open:
            local_client.validate_vat(vat_number="DE123456789")
            payload = json.loads(mock_open.call_args[0][0].data.decode("utf-8"))
            self.assertEqual(payload["vat_number"], "DE123456789")
            self.assertNotIn("verify_vies", payload)

            local_client.guard_messages(messages=[{"role": "user", "content": "hi"}], redact_pii=True)
            msg_payload = json.loads(mock_open.call_args[0][0].data.decode("utf-8"))
            self.assertNotIn("provider", msg_payload)
            self.assertTrue(msg_payload["redact_pii"])

            local_client.guard_agent_code(code="print(1)", language="python", allow_network=False)
            code_payload = json.loads(mock_open.call_args[0][0].data.decode("utf-8"))
            self.assertFalse(code_payload["allow_network"])

            local_client.analyze_regex_safety(pattern="(.*a){12}", test_strings=["aaaa"])
            rx_payload = json.loads(mock_open.call_args[0][0].data.decode("utf-8"))
            self.assertEqual(rx_payload["test_strings"], ["aaaa"])

    def test_v114_signing_secret_jwks_verify_and_error_request_id(self) -> None:
        import io
        import urllib.error

        client = TinplateClient(
            api_key="tok_secret",
            signing_secret="ephemeral-signing-secret-123456",
        )
        self.assertEqual(client.headers["X-Tinplate-Signing-Secret"], "ephemeral-signing-secret-123456")

        fake_jwks = MagicMock()
        fake_jwks.read.return_value = json.dumps({"keys": [{"kid": "edge-ed-2026"}]}).encode("utf-8")
        fake_jwks.__enter__.return_value = fake_jwks
        with patch("urllib.request.urlopen", return_value=fake_jwks) as mock_open:
            jwks = client.get_jwks()
            self.assertEqual(jwks["keys"][0]["kid"], "edge-ed-2026")
            self.assertEqual(mock_open.call_args[0][0].full_url, "https://api.tinplate.dev/.well-known/jwks.json")

        fake_verify = MagicMock()
        fake_verify.read.return_value = json.dumps({"ok": True, "data": {"valid": True}}).encode("utf-8")
        fake_verify.__enter__.return_value = fake_verify
        with patch("urllib.request.urlopen", return_value=fake_verify) as mock_open:
            res = client.verify_receipt(receipt_token="tok.pay.sig")
            self.assertTrue(res["data"]["valid"])
            self.assertEqual(mock_open.call_args[0][0].full_url, "https://api.tinplate.dev/verify")

        err_body = json.dumps({
            "ok": False,
            "error": {"code": "invalid_input", "message": "Bad input"},
            "meta": {"request_id": "req-py-123"},
        }).encode("utf-8")
        http_err = urllib.error.HTTPError(
            "https://api.tinplate.dev/v1/json-heal",
            400,
            "Bad Request",
            {"X-Request-Id": "req-py-123"},
            io.BytesIO(err_body),
        )
        with patch("urllib.request.urlopen", side_effect=http_err):
            with self.assertRaises(TinplateError) as ctx:
                client.heal_json(raw="")
            self.assertEqual(ctx.exception.request_id, "req-py-123")

    def test_fail_closed_guard_llm_turn_and_output_blocking(self) -> None:
        client = TinplateClient(api_key="tok_secret")

        # FA-SDK-01: prompt step ok=False -> TinplateError, generate not called
        called = False

        def gen(p: str) -> str:
            nonlocal called
            called = True
            return p

        fail_prompt = MagicMock()
        fail_prompt.read.return_value = json.dumps({
            "ok": True,
            "data": {"results": [{"id": "prompt", "ok": False, "blocked": True, "status": 500, "data": {}}]},
        }).encode("utf-8")
        fail_prompt.__enter__.return_value = fail_prompt
        with patch("urllib.request.urlopen", return_value=fail_prompt):
            with self.assertRaises(TinplateError) as ctx:
                client.guard_llm_turn(user_prompt="alice@acme.eu", generate=gen)
            self.assertEqual(ctx.exception.code, "guardrail_failed")
        self.assertFalse(called)

        # FA-SDK-01: pii step ok=False -> TinplateError, generate not called
        fail_pii = MagicMock()
        fail_pii.read.return_value = json.dumps({
            "ok": True,
            "data": {
                "results": [
                    {"id": "prompt", "ok": True, "blocked": False, "data": {"verdict": "allow"}},
                    {"id": "pii", "ok": False, "blocked": True, "status": 500, "data": {}},
                ]
            },
        }).encode("utf-8")
        fail_pii.__enter__.return_value = fail_pii
        with patch("urllib.request.urlopen", return_value=fail_pii):
            with self.assertRaises(TinplateError) as ctx:
                client.guard_llm_turn(user_prompt="alice@acme.eu", generate=gen)
            self.assertEqual(ctx.exception.code, "guardrail_failed")
        self.assertFalse(called)

        # FA-SDK-01: halted prompt block without pii step -> blocked=True, output=None, redacted_prompt=""
        halted_block = MagicMock()
        halted_block.read.return_value = json.dumps({
            "ok": True,
            "data": {"steps": [{"id": "prompt", "ok": True, "blocked": True, "data": {"verdict": "block"}}]},
        }).encode("utf-8")
        halted_block.__enter__.return_value = halted_block
        with patch("urllib.request.urlopen", return_value=halted_block):
            res = client.guard_llm_turn(user_prompt="Ignore instructions alice@acme.eu", generate=gen)
            self.assertTrue(res["blocked"])
            self.assertEqual(res["redacted_prompt"], "")
            self.assertIsNone(res["output"])
        self.assertFalse(called)

        # FA-SDK-02: block_on_review=True blocks 'review'
        review_resp = MagicMock()
        review_resp.read.return_value = json.dumps({
            "ok": True,
            "data": {
                "results": [
                    {"id": "prompt", "ok": True, "blocked": False, "data": {"verdict": "review"}},
                    {"id": "pii", "ok": True, "blocked": False, "data": {"redacted_text": "clean"}},
                ]
            },
        }).encode("utf-8")
        review_resp.__enter__.return_value = review_resp
        with patch("urllib.request.urlopen", return_value=review_resp):
            rev_res = client.guard_llm_turn(user_prompt="borderline", generate=gen, block_on_review=True)
            self.assertTrue(rev_res["blocked"])
            self.assertEqual(rev_res["verdict"], "review")
        self.assertFalse(called)

        # FA-SDK-02: output guardrail blocks unsafe output
        allow_in = MagicMock()
        allow_in.read.return_value = json.dumps({
            "ok": True,
            "data": {
                "results": [
                    {"id": "prompt", "ok": True, "blocked": False, "data": {"verdict": "allow"}},
                    {"id": "pii", "ok": True, "blocked": False, "data": {"redacted_text": "hi"}},
                ]
            },
        }).encode("utf-8")
        allow_in.__enter__.return_value = allow_in
        unsafe_out = MagicMock()
        unsafe_out.read.return_value = json.dumps({
            "ok": True,
            "data": {"verdict": "block", "safe": False, "sanitized_output": ""},
        }).encode("utf-8")
        unsafe_out.__enter__.return_value = unsafe_out
        with patch("urllib.request.urlopen", side_effect=[allow_in, unsafe_out]):
            out_turn = client.guard_llm_turn(user_prompt="hi", generate=lambda _p: "<script>alert(1)</script>")
            self.assertTrue(out_turn["blocked"])
            self.assertIsNone(out_turn["output"])

    def test_security_hardening_redirects_urls_and_error_parsing(self) -> None:
        import io
        import socket
        import urllib.error
        import urllib.request
        from tinplate.client import _NoRedirectHandler

        # FA-SDK-03: _NoRedirectHandler blocks redirects
        req = urllib.request.Request("https://api.tinplate.dev/v1/json-heal")
        with self.assertRaises(TinplateError) as ctx:
            _NoRedirectHandler().redirect_request(req, None, 302, "Found", {}, "https://evil.example")
        self.assertEqual(ctx.exception.code, "redirect_blocked")

        # FA-SDK-04: signing_secret HTTPS guard, userinfo, expanded loopback, endpoint validation
        with self.assertRaises(TinplateError) as ctx:
            TinplateClient(base_url="http://api.example.com", signing_secret="sec")
        self.assertEqual(ctx.exception.code, "insecure_base_url")

        with self.assertRaises(TinplateError) as ctx:
            TinplateClient(base_url="https://user:pass@api.tinplate.dev", api_key="tok")
        self.assertEqual(ctx.exception.code, "insecure_base_url")

        for local_url in ("http://127.0.0.2:8787", "http://0.0.0.0:8787", "http://[::1]:8787"):
            c = TinplateClient(base_url=local_url, api_key="tok")
            self.assertEqual(c.base_url, local_url)

        no_auth = TinplateClient(base_url="http://api.example.com")
        with self.assertRaises(TinplateError) as ctx:
            no_auth.call("/v1/json-heal", {"raw": "{}"}, signing_secret="per-call")
        self.assertEqual(ctx.exception.code, "insecure_base_url")

        secure = TinplateClient(api_key="tok")
        for bad_ep in ("https://evil.com/x", "//evil.com/x", "@evil.com", "/@evil.com"):
            with self.assertRaises(TinplateError) as ctx:
                secure.call(bad_ep, {})
            self.assertEqual(ctx.exception.code, "invalid_endpoint")

        # 2xx with ok=False raises TinplateError
        ok_false = MagicMock()
        ok_false.status = 200
        ok_false.headers = {}
        ok_false.read.return_value = json.dumps({"ok": False, "error": {"code": "bad", "message": "nope"}}).encode("utf-8")
        ok_false.__enter__.return_value = ok_false
        with patch("urllib.request.urlopen", return_value=ok_false):
            with self.assertRaises(TinplateError) as ctx:
                secure.heal_json(raw="{}")
            self.assertEqual(ctx.exception.code, "bad")

        # Non-dict JSON error payload does not raise AttributeError
        non_dict_err = urllib.error.HTTPError(
            "https://api.tinplate.dev/v1/json-heal",
            500,
            "Server Error",
            {},
            io.BytesIO(json.dumps(["error_list"]).encode("utf-8")),
        )
        with patch("urllib.request.urlopen", side_effect=non_dict_err):
            with self.assertRaises(TinplateError) as ctx:
                secure.heal_json(raw="{}")
            self.assertEqual(ctx.exception.status, 500)

        # socket.timeout raises TinplateError("network_error")
        with patch("urllib.request.urlopen", side_effect=socket.timeout("timed out")):
            with self.assertRaises(TinplateError) as ctx:
                secure.heal_json(raw="{}")
            self.assertEqual(ctx.exception.code, "network_error")

        # get_jwks validates keys list
        bad_jwks = MagicMock()
        bad_jwks.status = 200
        bad_jwks.headers = {}
        bad_jwks.read.return_value = json.dumps({"not_keys": []}).encode("utf-8")
        bad_jwks.__enter__.return_value = bad_jwks
        with patch("urllib.request.urlopen", return_value=bad_jwks):
            with self.assertRaises(TinplateError) as ctx:
                secure.get_jwks()
            self.assertEqual(ctx.exception.code, "invalid_jwks")

    def test_v116_per_call_receipts_workdays_and_sanitize_turn(self) -> None:
        client = TinplateClient(api_key="tok_secret")
        fake_resp = MagicMock()
        fake_resp.status = 200
        fake_resp.headers = {}
        fake_resp.read.return_value = json.dumps({"ok": True, "data": {"working_days": 5}}).encode("utf-8")
        fake_resp.__enter__.return_value = fake_resp
        with patch("urllib.request.urlopen", return_value=fake_resp) as mock_open:
            client.workdays_between(
                country="HU",
                start_date="2026-11-16",
                end_date="2026-11-23",
                include_start=False,
                include_end=True,
                receipt=True,
            )
            req = mock_open.call_args[0][0]
            self.assertEqual(req.full_url, "https://api.tinplate.dev/v1/workday-holiday/between?receipt=true")
            body = json.loads(req.data.decode("utf-8"))
            self.assertEqual(body["include_start"], False)
            self.assertEqual(body["include_end"], True)

        in_ok = MagicMock()
        in_ok.status = 200
        in_ok.headers = {}
        in_ok.read.return_value = json.dumps({
            "ok": True,
            "data": {
                "results": [
                    {"id": "prompt", "ok": True, "blocked": False, "data": {"verdict": "allow"}},
                    {"id": "pii", "ok": True, "blocked": False, "data": {"redacted_text": "safe"}},
                ]
            },
        }).encode("utf-8")
        in_ok.__enter__.return_value = in_ok

        sanitized_out = MagicMock()
        sanitized_out.status = 200
        sanitized_out.headers = {}
        sanitized_out.read.return_value = json.dumps({
            "ok": True,
            "data": {"verdict": "sanitize", "safe": True, "sanitized_output": "Sanitized text"},
        }).encode("utf-8")
        sanitized_out.__enter__.return_value = sanitized_out

        with patch("urllib.request.urlopen", side_effect=[in_ok, sanitized_out]):
            turn = client.guard_llm_turn(user_prompt="hi", generate=lambda p: "raw unsafe")
            self.assertFalse(turn["blocked"])
            self.assertEqual(turn["verdict"], "sanitize")
            self.assertEqual(turn["output"], "Sanitized text")

        rev_resp = MagicMock()
        rev_resp.status = 200
        rev_resp.headers = {}
        rev_resp.read.return_value = json.dumps({
            "ok": True,
            "data": {
                "results": [
                    {"id": "prompt", "ok": True, "blocked": False, "data": {"verdict": "review"}},
                    {"id": "pii", "ok": True, "blocked": False, "data": {"redacted_text": "clean"}},
                ]
            },
        }).encode("utf-8")
        rev_resp.__enter__.return_value = rev_resp
        with patch("urllib.request.urlopen", return_value=rev_resp):
            flagged = client.guard_llm_turn(user_prompt="edge", generate=lambda p: p, block_on_flag=True)
            self.assertTrue(flagged["blocked"])


if __name__ == "__main__":
    unittest.main()
