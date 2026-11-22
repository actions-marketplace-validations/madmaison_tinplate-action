"""Zero-dependency HTTP client for the Tinplate 34-API Edge Gateway."""

from __future__ import annotations

import json
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Tuple

_SDK_VERSION = "1.1.10"

_STDLIB_URLOPEN = urllib.request.urlopen
_SCHEME_PREFIX_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
_WS_OR_CTRL_RE = re.compile(r"[\s\x00-\x1f\x7f\\]")


class TinplateError(Exception):
    """Raised when the Tinplate gateway returns a non-2xx or ok=false response."""

    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        request_id: Optional[str] = None,
    ) -> None:
        super().__init__(f"Tinplate API error ({status} {code}): {message}")
        self.status = status
        self.code = code
        self.message = message
        self.request_id = request_id


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Block HTTP redirects to prevent forwarding credentials to unintended hosts."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> Optional[urllib.request.Request]:
        if fp is not None:
            try:
                fp.close()
            except Exception:
                pass
        req_id = headers.get("X-Request-Id") if headers else None
        raise TinplateError(
            code,
            "redirect_blocked",
            f"Refusing HTTP {code} redirect to '{newurl}'",
            request_id=req_id,
        )


def _is_local_host(hostname: Optional[str]) -> bool:
    if not hostname:
        return False
    h = hostname.lower()
    if h in ("localhost", "0.0.0.0", "::1", "[::1]") or h.endswith(".localhost"):
        return True
    parts = h.split(".")
    if len(parts) == 4 and parts[0] == "127":
        return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
    return False


_BLOCKING_VERDICTS = frozenset({
    "block",
    "fail",
    "reject",
    "ungrounded",
    "contradicted",
    "vulnerable",
    "invalid",
})
_ESCALATED_VERDICTS = frozenset({"review", "warn", "flagged", "partially_grounded"})
_NON_BLOCKING_VERDICTS = frozenset({
    "allow",
    "safe",
    "pass",
    "grounded",
    "clean",
    "sanitize",
    "sanitized",
    "repaired",
})


def _is_output_blocked(out_data: Any, *, block_on_review: bool = False) -> bool:
    """Decide whether a guardrail payload blocks execution, checking `verdict` before `safe`."""
    if not isinstance(out_data, dict):
        return True
    verdict = out_data.get("verdict")
    if isinstance(verdict, str):
        if verdict in _BLOCKING_VERDICTS:
            return True
        if verdict in _ESCALATED_VERDICTS:
            return block_on_review
        if verdict in _NON_BLOCKING_VERDICTS:
            return False
    return out_data.get("safe") is False or out_data.get("allowed") is False


def _validate_input_guardrail_pipeline(
    pre: Dict[str, Any],
    *,
    prompt_id: str = "prompt",
    pii_id: str = "pii",
    block_on_review: bool = False,
) -> Tuple[bool, str, str]:
    """Validate prompt+PII guardrail pipeline results fail-closed."""
    meta = pre.get("meta")
    req_id = meta.get("request_id") if isinstance(meta, dict) else None
    data = pre.get("data")
    if not isinstance(data, dict):
        raise TinplateError(
            502,
            "guardrail_failed",
            "Input guardrail pipeline returned invalid data",
            request_id=req_id,
        )
    steps = data.get("results")
    if steps is None:
        steps = data.get("steps")
    if not isinstance(steps, list) or not steps:
        raise TinplateError(
            502,
            "guardrail_failed",
            "Input guardrail pipeline returned no step results",
            request_id=req_id,
        )

    first_step = steps[0] if isinstance(steps[0], dict) else None
    prompt_step = next(
        (s for s in steps if isinstance(s, dict) and s.get("id") == prompt_id),
        first_step,
    )
    if not isinstance(prompt_step, dict) or prompt_step.get("ok") is not True:
        raw_status = prompt_step.get("status") if isinstance(prompt_step, dict) else None
        status = raw_status if isinstance(raw_status, int) and raw_status >= 400 else 502
        raise TinplateError(
            status,
            "guardrail_failed",
            "Prompt guardrail step failed",
            request_id=req_id,
        )

    prompt_data = prompt_step.get("data")
    if not isinstance(prompt_data, dict) or not isinstance(prompt_data.get("verdict"), str):
        raise TinplateError(
            502,
            "guardrail_failed",
            "Prompt guardrail step returned no verdict",
            request_id=req_id,
        )

    verdict = prompt_data["verdict"]
    prompt_blocked = (
        prompt_step.get("blocked") is True
        or verdict == "block"
        or (block_on_review and verdict == "review")
    )

    second_step = steps[1] if len(steps) > 1 and isinstance(steps[1], dict) else None
    pii_step = next(
        (s for s in steps if isinstance(s, dict) and s.get("id") == pii_id),
        second_step,
    )
    pii_data = (
        pii_step.get("data")
        if isinstance(pii_step, dict) and isinstance(pii_step.get("data"), dict)
        else {}
    )

    if prompt_blocked:
        redacted = (
            pii_data["redacted_text"]
            if (
                isinstance(pii_step, dict)
                and pii_step.get("ok") is True
                and isinstance(pii_data.get("redacted_text"), str)
            )
            else ""
        )
        return True, verdict, redacted

    if (
        not isinstance(pii_step, dict)
        or pii_step.get("ok") is not True
        or not isinstance(pii_data.get("redacted_text"), str)
    ):
        raw_status = pii_step.get("status") if isinstance(pii_step, dict) else None
        status = raw_status if isinstance(raw_status, int) and raw_status >= 400 else 502
        raise TinplateError(
            status,
            "guardrail_failed",
            "PII redaction step failed",
            request_id=req_id,
        )

    return False, verdict, pii_data["redacted_text"]


class TinplateClient:
    """Zero-dependency client for Tinplate /v1/* endpoints, /v1/pipeline, and /v1/presets.

    Pass `zyla_api_key` together with `base_url` pointing at your subscribed Zyla endpoint host URL.
    """

    def __init__(
        self,
        *,
        base_url: str = "https://api.tinplate.dev",
        allow_insecure: bool = False,
        api_key: Optional[str] = None,
        rapidapi_key: Optional[str] = None,
        rapidapi_host: Optional[str] = None,
        zyla_api_key: Optional[str] = None,
        request_receipts: bool = False,
        signing_secret: Optional[str] = None,
        timeout: float = 8.0,
        max_retries: int = 2,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        parsed = urllib.parse.urlparse(self.base_url)
        if parsed.scheme not in ("https", "http") or not parsed.netloc:
            raise TinplateError(
                0,
                "invalid_base_url",
                f"Invalid Tinplate base_url '{self.base_url}'.",
            )
        if parsed.username or parsed.password:
            raise TinplateError(
                0,
                "insecure_base_url",
                "Refusing base_url with embedded credentials.",
            )

        self._allow_insecure = allow_insecure
        self._is_secure_or_local_base = (
            parsed.scheme == "https" or _is_local_host(parsed.hostname)
        )
        self._base_scheme = parsed.scheme
        self._base_netloc = parsed.netloc

        has_auth = bool(api_key or zyla_api_key or rapidapi_key or signing_secret)
        if has_auth and not self._is_secure_or_local_base and not allow_insecure:
            raise TinplateError(
                0,
                "insecure_base_url",
                f"Refusing to send Tinplate credentials over non-HTTPS base_url '{self.base_url}'. Pass allow_insecure=True only for controlled testing.",
            )

        self.request_receipts = request_receipts
        self.timeout = timeout
        self.max_retries = max(0, max_retries)
        self.headers: Dict[str, str] = {
            "Content-Type": "application/json",
            "User-Agent": f"tinplate-python/{_SDK_VERSION}",
        }

        if api_key:
            self.headers["Authorization"] = f"Bearer {api_key}"
        elif zyla_api_key:
            self.headers["Authorization"] = f"Bearer {zyla_api_key}"

        if rapidapi_key:
            self.headers["X-RapidAPI-Key"] = rapidapi_key
        if rapidapi_host:
            self.headers["X-RapidAPI-Host"] = rapidapi_host
        if request_receipts:
            self.headers["X-Tinplate-Receipt-Request"] = "true"
        if signing_secret:
            self.headers["X-Tinplate-Signing-Secret"] = signing_secret

    def _build_endpoint_url(self, endpoint: str) -> str:
        if (
            not endpoint
            or _WS_OR_CTRL_RE.search(endpoint)
            or "://" in endpoint
            or _SCHEME_PREFIX_RE.match(endpoint)
        ):
            raise TinplateError(0, "invalid_endpoint", f"Invalid Tinplate endpoint '{endpoint}'.")
        path = endpoint if endpoint.startswith("/") else f"/v1/{endpoint}"
        path_only = path.split("?", 1)[0].split("#", 1)[0]
        if path.startswith("//") or "@" in path_only:
            raise TinplateError(0, "invalid_endpoint", f"Invalid Tinplate endpoint '{endpoint}'.")
        url = f"{self.base_url}{path}"
        parsed_url = urllib.parse.urlparse(url)
        if (
            parsed_url.scheme != self._base_scheme
            or parsed_url.netloc != self._base_netloc
            or parsed_url.username
            or parsed_url.password
        ):
            raise TinplateError(
                0,
                "invalid_endpoint",
                f"Endpoint '{endpoint}' resolves outside configured base_url.",
            )
        return url

    def _open_request(self, req: urllib.request.Request) -> Any:
        if urllib.request.urlopen is not _STDLIB_URLOPEN:
            return urllib.request.urlopen(req, timeout=self.timeout)
        opener = urllib.request.build_opener(_NoRedirectHandler())
        return opener.open(req, timeout=self.timeout)

    def _request(
        self,
        method: str,
        endpoint: str,
        body: Optional[Dict[str, Any]] = None,
        *,
        receipt: Optional[bool] = None,
        signing_secret: Optional[str] = None,
    ) -> Dict[str, Any]:
        if signing_secret and not self._is_secure_or_local_base and not self._allow_insecure:
            raise TinplateError(
                0,
                "insecure_base_url",
                f"Refusing to send Tinplate signing_secret over non-HTTPS base_url '{self.base_url}'. Pass allow_insecure=True only for controlled testing.",
            )

        url = self._build_endpoint_url(endpoint)
        want_receipt = method == "POST" and (
            self.request_receipts if receipt is None else receipt
        )
        if want_receipt:
            sep = "&" if "?" in url else "?"
            url = f"{url}{sep}receipt=true"

        req_headers = dict(self.headers)
        if signing_secret:
            req_headers["X-Tinplate-Signing-Secret"] = signing_secret
        if not want_receipt:
            req_headers.pop("X-Tinplate-Receipt-Request", None)
        if endpoint == "/.well-known/jwks.json":
            req_headers.pop("Authorization", None)
            req_headers.pop("X-RapidAPI-Key", None)
            req_headers.pop("X-RapidAPI-Host", None)
            req_headers.pop("X-Tinplate-Signing-Secret", None)
        if method == "GET":
            req_headers.pop("Content-Type", None)

        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(
            url,
            data=data,
            headers=req_headers,
            method=method,
        )

        attempt = 0
        while True:
            try:
                with self._open_request(req) as resp:
                    resp_status = getattr(resp, "status", 200)
                    resp_headers = getattr(resp, "headers", None)
                    header_req_id = resp_headers.get("X-Request-Id") if resp_headers else None
                    if isinstance(resp_status, int) and 300 <= resp_status < 400:
                        raise TinplateError(
                            resp_status,
                            "redirect_blocked",
                            f"Refusing HTTP {resp_status} redirect from Tinplate endpoint.",
                            request_id=header_req_id,
                        )
                    raw = resp.read().decode("utf-8")
                    try:
                        parsed = json.loads(raw)
                    except json.JSONDecodeError as dec_err:
                        status_code = resp_status if isinstance(resp_status, int) else 0
                        raise TinplateError(
                            status_code,
                            "invalid_response",
                            f"Tinplate API returned non-JSON response (HTTP {status_code}): {raw[:200]}",
                            request_id=header_req_id,
                        ) from dec_err

                    if not isinstance(parsed, dict):
                        status_code = resp_status if isinstance(resp_status, int) else 0
                        raise TinplateError(
                            status_code,
                            "invalid_response",
                            f"Tinplate API returned non-object JSON (HTTP {status_code})",
                            request_id=header_req_id,
                        )

                    if not parsed.get("ok", True):
                        raw_err_obj = parsed.get("error")
                        err_obj = raw_err_obj if isinstance(raw_err_obj, dict) else {}
                        raw_meta = parsed.get("meta")
                        meta_obj = raw_meta if isinstance(raw_meta, dict) else {}
                        req_id = meta_obj.get("request_id") or header_req_id
                        status_code = resp_status if isinstance(resp_status, int) else 200
                        raise TinplateError(
                            status_code,
                            str(err_obj.get("code", "api_error")),
                            str(err_obj.get("message", "Tinplate API returned ok=false")),
                            request_id=req_id,
                        )

                    receipt_token = resp_headers.get("X-Tinplate-Receipt") if resp_headers else None
                    receipt_hash = resp_headers.get("X-Tinplate-Receipt-Hash") if resp_headers else None
                    if receipt_token or receipt_hash:
                        parsed["receipt"] = {"token": receipt_token, "hash": receipt_hash}
                    return parsed
            except urllib.error.HTTPError as exc:
                if exc.code in (429, 503) and attempt < self.max_retries:
                    attempt += 1
                    retry_after = exc.headers.get("Retry-After") if exc.headers else None
                    try:
                        delay = min(float(retry_after), 2.0) if retry_after else min(0.15 * (2 ** (attempt - 1)), 1.5)
                    except ValueError:
                        delay = 0.25
                    time.sleep(max(0.0, delay))
                    continue

                raw_err = exc.read().decode("utf-8", errors="replace")
                header_req_id = exc.headers.get("X-Request-Id") if exc.headers else None
                try:
                    err_json = json.loads(raw_err)
                except json.JSONDecodeError as dec_err:
                    raise TinplateError(
                        exc.code,
                        "http_error",
                        raw_err,
                        request_id=header_req_id,
                    ) from dec_err

                if isinstance(err_json, dict):
                    raw_err_obj = err_json.get("error")
                    err_obj = raw_err_obj if isinstance(raw_err_obj, dict) else {}
                    raw_meta = err_json.get("meta")
                    meta_obj = raw_meta if isinstance(raw_meta, dict) else {}
                    req_id = meta_obj.get("request_id") or header_req_id
                    code = str(err_obj.get("code", "http_error"))
                    message = str(err_obj.get("message", raw_err))
                else:
                    req_id = header_req_id
                    code = "http_error"
                    message = raw_err
                raise TinplateError(
                    exc.code,
                    code,
                    message,
                    request_id=req_id,
                ) from exc
            except (urllib.error.URLError, TimeoutError, socket.timeout) as exc:
                raise TinplateError(0, "network_error", str(exc)) from exc

    def call(
        self,
        endpoint: str,
        body: Dict[str, Any],
        *,
        receipt: Optional[bool] = None,
        signing_secret: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Invoke any Tinplate /v1/* endpoint and return the parsed JSON envelope."""
        return self._request(
            "POST",
            endpoint,
            body,
            receipt=receipt,
            signing_secret=signing_secret,
        )

    def get_jwks(self) -> Dict[str, Any]:
        """Fetch public Ed25519/ES256 receipt verification JWKS (`GET /.well-known/jwks.json`)."""
        res = self._request("GET", "/.well-known/jwks.json", receipt=False)
        if not isinstance(res.get("keys"), list):
            raise TinplateError(0, "invalid_jwks", "JWKS response missing keys list")
        return res

    def verify_receipt(
        self,
        *,
        receipt_token: Optional[str] = None,
        chain: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Verify a receipt token or chain against the gateway (`POST /verify`)."""
        payload: Dict[str, Any] = {}
        if receipt_token is not None:
            payload["receipt_token"] = receipt_token
        if chain is not None:
            payload["chain"] = chain
        return self._request("POST", "/verify", payload, receipt=False)

    def health(self) -> Dict[str, Any]:
        """Check gateway health (`GET /v1/health`)."""
        return self._request("GET", "/v1/health")

    def list_presets(self) -> Dict[str, Any]:
        """List built-in enterprise pipeline presets (`GET /v1/presets`)."""
        return self._request("GET", "/v1/presets")

    def _call_kwargs(self, endpoint: str, kwargs: Dict[str, Any]) -> Dict[str, Any]:
        params = dict(kwargs)
        receipt = params.pop("receipt", None)
        signing_secret = params.pop("signing_secret", None)
        return self.call(endpoint, params, receipt=receipt, signing_secret=signing_secret)

    def pipeline(
        self,
        steps: List[Dict[str, Any]],
        *,
        stop_on_block: bool = True,
        parallel: bool = False,
        receipt: Optional[bool] = None,
        signing_secret: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Chain up to 5 Tinplate APIs in a single request with $steps piping."""
        payload: Dict[str, Any] = {"stop_on_block": stop_on_block, "steps": steps}
        if parallel:
            payload["parallel"] = True
        return self.call(
            "/v1/pipeline",
            payload,
            receipt=receipt,
            signing_secret=signing_secret,
        )

    def preset(
        self,
        preset_id: str,
        input_data: Dict[str, Any],
        *,
        receipt: Optional[bool] = None,
        signing_secret: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Execute a named 1-call enterprise policy bundle."""
        return self.call(
            f"/v1/presets/{urllib.parse.quote(preset_id, safe='')}",
            input_data,
            receipt=receipt,
            signing_secret=signing_secret,
        )

    def prompt_guard(
        self,
        *,
        text: str,
        context: str = "user_input",
        sensitivity: str = "medium",
        block_threshold: Optional[int] = None,
        use_ai_judge: bool = False,
        receipt: Optional[bool] = None,
        signing_secret: Optional[str] = None,
    ) -> Dict[str, Any]:
        """01 — Prompt Injection Detection API."""
        payload: Dict[str, Any] = {
            "text": text,
            "context": context,
            "sensitivity": sensitivity,
            "use_ai_judge": use_ai_judge,
        }
        if block_threshold is not None:
            payload["block_threshold"] = block_threshold
        return self.call("/v1/prompt-guard", payload, receipt=receipt, signing_secret=signing_secret)

    def redact_pii(
        self,
        *,
        text: str,
        locales: Optional[List[str]] = None,
        mode: str = "token",
        types: Optional[List[str]] = None,
        receipt: Optional[bool] = None,
        signing_secret: Optional[str] = None,
    ) -> Dict[str, Any]:
        """03 — PII Redactor API."""
        payload: Dict[str, Any] = {"text": text, "mode": mode}
        if locales is not None:
            payload["locales"] = locales
        if types is not None:
            payload["types"] = types
        return self.call("/v1/pii-redactor", payload, receipt=receipt, signing_secret=signing_secret)

    def heal_json(
        self,
        *,
        raw: str,
        schema: Optional[Dict[str, Any]] = None,
        receipt: Optional[bool] = None,
        signing_secret: Optional[str] = None,
    ) -> Dict[str, Any]:
        """10 — Broken JSON & LLM Output Healer API."""
        payload: Dict[str, Any] = {"raw": raw}
        if schema is not None:
            payload["schema"] = schema
        return self.call("/v1/json-heal", payload, receipt=receipt, signing_secret=signing_secret)

    def scan_secrets(
        self,
        *,
        text: str,
        mode: str = "token",
        types: Optional[List[str]] = None,
        diff_only_added: bool = False,
        min_entropy: Optional[float] = None,
        receipt: Optional[bool] = None,
        signing_secret: Optional[str] = None,
    ) -> Dict[str, Any]:
        """16 — Log Redact & Secret Scanner API."""
        payload: Dict[str, Any] = {
            "text": text,
            "mode": mode,
            "diff_only_added": diff_only_added,
        }
        if types is not None:
            payload["types"] = types
        if min_entropy is not None:
            payload["min_entropy"] = min_entropy
        return self.call("/v1/secret-scanner", payload, receipt=receipt, signing_secret=signing_secret)

    def guard_llm_output(
        self,
        *,
        output: str,
        system_prompt: Optional[str] = None,
        canary_tokens: Optional[List[str]] = None,
        blocked_terms: Optional[List[str]] = None,
        allowed_link_domains: Optional[List[str]] = None,
        check_regulated_advice: Optional[bool] = None,
        receipt: Optional[bool] = None,
        signing_secret: Optional[str] = None,
    ) -> Dict[str, Any]:
        """31 — LLM Output Guardrail & Leak Detector API."""
        payload: Dict[str, Any] = {"output": output}
        if system_prompt is not None:
            payload["system_prompt"] = system_prompt
        if canary_tokens is not None:
            payload["canary_tokens"] = canary_tokens
        if blocked_terms is not None:
            payload["blocked_terms"] = blocked_terms
        if allowed_link_domains is not None:
            payload["allowed_link_domains"] = allowed_link_domains
        if check_regulated_advice is not None:
            payload["check_regulated_advice"] = check_regulated_advice
        return self.call("/v1/llm-output-guard", payload, receipt=receipt, signing_secret=signing_secret)

    def guard_messages(
        self,
        *,
        messages: List[Dict[str, Any]],
        sensitivity: str = "medium",
        check_prompt_injection: bool = True,
        redact_pii: bool = True,
        scan_secrets: bool = True,
        strip_email_quotes: bool = False,
        locales: Optional[List[str]] = None,
        receipt: Optional[bool] = None,
        signing_secret: Optional[str] = None,
    ) -> Dict[str, Any]:
        """37 — LLM Chat Messages Policy Proxy API."""
        payload: Dict[str, Any] = {
            "messages": messages,
            "sensitivity": sensitivity,
            "check_prompt_injection": check_prompt_injection,
            "redact_pii": redact_pii,
            "scan_secrets": scan_secrets,
            "strip_email_quotes": strip_email_quotes,
        }
        if locales is not None:
            payload["locales"] = locales
        return self.call("/v1/llm-messages-guard", payload, receipt=receipt, signing_secret=signing_secret)

    def guard_agent_code(
        self,
        *,
        code: str,
        language: str = "auto",
        allow_network: bool = False,
        allow_filesystem_write: bool = False,
        receipt: Optional[bool] = None,
        signing_secret: Optional[str] = None,
    ) -> Dict[str, Any]:
        """42 — AI-Generated Code & CI Workflow Sandbox Auditor API."""
        return self.call(
            "/v1/agent-code-guard",
            {
                "code": code,
                "language": language,
                "allow_network": allow_network,
                "allow_filesystem_write": allow_filesystem_write,
            },
            receipt=receipt,
            signing_secret=signing_secret,
        )

    def restore_pii(
        self,
        *,
        redacted_text: str,
        tokens: Dict[str, str],
        receipt: Optional[bool] = None,
        signing_secret: Optional[str] = None,
    ) -> Dict[str, Any]:
        """03 — PII Redactor Restore API."""
        return self.call(
            "/v1/pii-redactor/restore",
            {"redacted_text": redacted_text, "tokens": tokens},
            receipt=receipt,
            signing_secret=signing_secret,
        )

    def validate_iban(
        self,
        *,
        iban: str,
        bic: Optional[str] = None,
        receipt: Optional[bool] = None,
        signing_secret: Optional[str] = None,
    ) -> Dict[str, Any]:
        """05 — EU IBAN & BIC Validator API."""
        payload: Dict[str, Any] = {"iban": iban}
        if bic is not None:
            payload["bic"] = bic
        return self.call("/v1/eu-vat-iban/iban", payload, receipt=receipt, signing_secret=signing_secret)

    def validate_vat(
        self,
        *,
        vat_number: str,
        verify_vies: Optional[bool] = None,
        receipt: Optional[bool] = None,
        signing_secret: Optional[str] = None,
    ) -> Dict[str, Any]:
        """05 — EU VAT Number Format Validator API (offline syntax/checksum only)."""
        payload: Dict[str, Any] = {"vat_number": vat_number}
        if verify_vies is not None:
            payload["verify_vies"] = verify_vies
        return self.call(
            "/v1/eu-vat-iban/vat",
            payload,
            receipt=receipt,
            signing_secret=signing_secret,
        )

    def email_dns(self, **kwargs: Any) -> Dict[str, Any]:
        """06 — Email DNS & Deliverability Audit API."""
        return self._call_kwargs("/v1/email-dns", kwargs)

    def ua_bot_parser(
        self,
        *,
        user_agent: str,
        receipt: Optional[bool] = None,
        signing_secret: Optional[str] = None,
    ) -> Dict[str, Any]:
        """08 — User-Agent & AI Bot Parser API."""
        return self.call(
            "/v1/ua-bot-parser",
            {"user_agent": user_agent},
            receipt=receipt,
            signing_secret=signing_secret,
        )

    def workdays_between(
        self,
        *,
        country: str,
        start_date: str,
        end_date: str,
        include_start: Optional[bool] = None,
        include_end: Optional[bool] = None,
        receipt: Optional[bool] = None,
        signing_secret: Optional[str] = None,
    ) -> Dict[str, Any]:
        """09 — EU Workdays Between Dates API."""
        payload: Dict[str, Any] = {
            "country": country,
            "start_date": start_date,
            "end_date": end_date,
        }
        if include_start is not None:
            payload["include_start"] = include_start
        if include_end is not None:
            payload["include_end"] = include_end
        return self.call(
            "/v1/workday-holiday/between",
            payload,
            receipt=receipt,
            signing_secret=signing_secret,
        )

    def add_workdays(
        self,
        *,
        country: str,
        date: str,
        days: int,
        receipt: Optional[bool] = None,
        signing_secret: Optional[str] = None,
    ) -> Dict[str, Any]:
        """09 — Add EU Workdays API."""
        return self.call(
            "/v1/workday-holiday/add",
            {"country": country, "date": date, "days": days},
            receipt=receipt,
            signing_secret=signing_secret,
        )

    def is_workday(
        self,
        *,
        country: str,
        date: str,
        receipt: Optional[bool] = None,
        signing_secret: Optional[str] = None,
    ) -> Dict[str, Any]:
        """09 — Check EU Workday API."""
        return self.call(
            "/v1/workday-holiday/is-workday",
            {"country": country, "date": date},
            receipt=receipt,
            signing_secret=signing_secret,
        )

    def schema_diff(self, **kwargs: Any) -> Dict[str, Any]:
        """11 — JSON Schema Breaking-Change Diff API."""
        return self._call_kwargs("/v1/schema-diff", kwargs)

    def ssrf_firewall(self, **kwargs: Any) -> Dict[str, Any]:
        """13 — Outbound SSRF Firewall API."""
        return self._call_kwargs("/v1/ssrf-firewall", kwargs)

    def hallucination_diff(self, **kwargs: Any) -> Dict[str, Any]:
        """14 — RAG Hallucination & Citation Diff API."""
        return self._call_kwargs("/v1/hallucination-diff", kwargs)

    def issue_consent_token(self, **kwargs: Any) -> Dict[str, Any]:
        """15 — Consent Token Issuer API."""
        return self._call_kwargs("/v1/consent-tokens/issue", kwargs)

    def verify_consent_token(self, **kwargs: Any) -> Dict[str, Any]:
        """15 — Consent Token Verifier API."""
        return self._call_kwargs("/v1/consent-tokens/verify", kwargs)

    def restore_secrets(
        self,
        *,
        redacted_text: str,
        tokens: Dict[str, str],
        receipt: Optional[bool] = None,
        signing_secret: Optional[str] = None,
    ) -> Dict[str, Any]:
        """16 — Secret Scanner Restore API."""
        return self.call(
            "/v1/secret-scanner/restore",
            {"redacted_text": redacted_text, "tokens": tokens},
            receipt=receipt,
            signing_secret=signing_secret,
        )

    def validate_tool_call(self, **kwargs: Any) -> Dict[str, Any]:
        """17 — LLM Tool-Call Validator & Repair API."""
        return self._call_kwargs("/v1/tool-call-validator", kwargs)

    def explain_cron(self, **kwargs: Any) -> Dict[str, Any]:
        """18 — Cron Expression Explainer API."""
        return self._call_kwargs("/v1/cron-explainer", kwargs)

    def lint_mcp_manifest(self, **kwargs: Any) -> Dict[str, Any]:
        """19 — MCP Manifest Security Linter API."""
        return self._call_kwargs("/v1/mcp-manifest-linter", kwargs)

    def normalize_url(self, **kwargs: Any) -> Dict[str, Any]:
        """21 — URL Normalizer & Tracking Stripper API."""
        return self._call_kwargs("/v1/url-normalizer", kwargs)

    def parse_locale_values(self, **kwargs: Any) -> Dict[str, Any]:
        """22 — Locale Number, Currency & Date Parser API."""
        return self._call_kwargs("/v1/locale-value-parser", kwargs)

    def validate_hu_business(self, **kwargs: Any) -> Dict[str, Any]:
        """23 — Hungarian Business & Tax ID Validator API."""
        return self._call_kwargs("/v1/hu-business-validator", kwargs)

    def generate_email_dns(self, **kwargs: Any) -> Dict[str, Any]:
        """24 — SPF/DKIM/DMARC Record Generator API."""
        return self._call_kwargs("/v1/email-dns-generator", kwargs)

    def sanitize_ics(self, **kwargs: Any) -> Dict[str, Any]:
        """25 — ICS Calendar Feed Sanitizer API."""
        return self._call_kwargs("/v1/ics-sanitizer", kwargs)

    def judge_semver_lockfile(self, **kwargs: Any) -> Dict[str, Any]:
        """27 — Semver & Lockfile Risk Judge API."""
        return self._call_kwargs("/v1/semver-lockfile-judge", kwargs)

    def budget_prompt_cache(self, **kwargs: Any) -> Dict[str, Any]:
        """28 — LLM Prompt Cache & Token Budgeter API."""
        return self._call_kwargs("/v1/prompt-cache-budgeter", kwargs)

    def issue_action_receipt(self, **kwargs: Any) -> Dict[str, Any]:
        """29 — Agent Action Receipt Issuer API."""
        return self._call_kwargs("/v1/agent-action-receipts/issue", kwargs)

    def verify_action_receipt(self, **kwargs: Any) -> Dict[str, Any]:
        """29 — Agent Action Receipt Verifier API."""
        return self._call_kwargs("/v1/agent-action-receipts/verify", kwargs)

    def inspect_provenance(self, **kwargs: Any) -> Dict[str, Any]:
        """30 — Content Provenance & C2PA Inspector API."""
        return self._call_kwargs("/v1/content-provenance", kwargs)

    def guard_command_sql(self, **kwargs: Any) -> Dict[str, Any]:
        """32 — Shell Command & SQL Injection Guard API."""
        return self._call_kwargs("/v1/command-sql-guard", kwargs)

    def inspect_jwt_jwk(self, **kwargs: Any) -> Dict[str, Any]:
        """34 — JWT & JWK Security Inspector API."""
        return self._call_kwargs("/v1/jwt-jwk-inspector", kwargs)

    def chunk_rag(self, **kwargs: Any) -> Dict[str, Any]:
        """35 — Markdown & Semantic RAG Chunker API."""
        return self._call_kwargs("/v1/rag-chunker", kwargs)

    def analyze_regex_safety(
        self,
        *,
        pattern: str,
        flags: str = "",
        test_strings: Optional[List[str]] = None,
        receipt: Optional[bool] = None,
        signing_secret: Optional[str] = None,
    ) -> Dict[str, Any]:
        """36 — Regex ReDoS Safety Analyzer API."""
        payload: Dict[str, Any] = {"pattern": pattern, "flags": flags}
        if test_strings is not None:
            payload["test_strings"] = test_strings
        return self.call("/v1/regex-safety", payload, receipt=receipt, signing_secret=signing_secret)

    def clean_tabular_rag(self, **kwargs: Any) -> Dict[str, Any]:
        """38 — Tabular CSV/JSON RAG Cleaner API."""
        return self._call_kwargs("/v1/tabular-rag-cleaner", kwargs)

    def parse_omnibar(
        self,
        *,
        text: str,
        now: Optional[str] = None,
        timezone: Optional[str] = None,
        default_currency: Optional[str] = None,
        locale: Optional[str] = None,
        last_answer: Optional[float] = None,
        user_weight_kg: Optional[float] = None,
        fx_rates: Optional[Dict[str, float]] = None,
        domains: Optional[List[str]] = None,
        projects: Optional[List[Dict[str, Any]]] = None,
        custom_routes: Optional[List[Dict[str, Any]]] = None,
        macros: Optional[Dict[str, str]] = None,
        wake_words: Optional[List[str]] = None,
        snapshot: Optional[Dict[str, Any]] = None,
        previous_intent: Optional[Dict[str, Any]] = None,
        custom_foods: Optional[List[Dict[str, Any]]] = None,
        custom_slash_commands: Optional[List[Dict[str, Any]]] = None,
        allow_compound: Optional[bool] = None,
        include_tokens: Optional[bool] = None,
        include_spans: Optional[bool] = None,
        include_alternatives: Optional[bool] = None,
        include_sentiment: Optional[bool] = None,
        include_ics: Optional[bool] = None,
        receipt: Optional[bool] = None,
        signing_secret: Optional[str] = None,
    ) -> Dict[str, Any]:
        """43 — Natural Language Command, Intent & Agent Router API (`POST /v1/omnibar/parse`)."""
        payload: Dict[str, Any] = {"text": text}
        for key, value in (
            ("now", now),
            ("timezone", timezone),
            ("default_currency", default_currency),
            ("locale", locale),
            ("last_answer", last_answer),
            ("user_weight_kg", user_weight_kg),
            ("fx_rates", fx_rates),
            ("domains", domains),
            ("projects", projects),
            ("custom_routes", custom_routes),
            ("macros", macros),
            ("wake_words", wake_words),
            ("snapshot", snapshot),
            ("previous_intent", previous_intent),
            ("custom_foods", custom_foods),
            ("custom_slash_commands", custom_slash_commands),
            ("allow_compound", allow_compound),
            ("include_tokens", include_tokens),
            ("include_spans", include_spans),
            ("include_alternatives", include_alternatives),
            ("include_sentiment", include_sentiment),
            ("include_ics", include_ics),
        ):
            if value is not None:
                payload[key] = value
        return self.call("/v1/omnibar/parse", payload, receipt=receipt, signing_secret=signing_secret)

    def suggest_omnibar(
        self,
        *,
        text: str,
        limit: Optional[int] = None,
        domains: Optional[List[str]] = None,
        projects: Optional[List[Dict[str, Any]]] = None,
        snapshot: Optional[Dict[str, Any]] = None,
        macros: Optional[Dict[str, str]] = None,
        custom_routes: Optional[List[Dict[str, Any]]] = None,
        custom_foods: Optional[List[Dict[str, Any]]] = None,
        custom_slash_commands: Optional[List[Dict[str, Any]]] = None,
        receipt: Optional[bool] = None,
        signing_secret: Optional[str] = None,
    ) -> Dict[str, Any]:
        """43 — Sub-0.2 ms Omnibar Ghost-Text & Ranked Autocomplete (`POST /v1/omnibar/suggest`)."""
        payload: Dict[str, Any] = {"text": text}
        for key, value in (
            ("limit", limit),
            ("domains", domains),
            ("projects", projects),
            ("snapshot", snapshot),
            ("macros", macros),
            ("custom_routes", custom_routes),
            ("custom_foods", custom_foods),
            ("custom_slash_commands", custom_slash_commands),
        ):
            if value is not None:
                payload[key] = value
        return self.call("/v1/omnibar/suggest", payload, receipt=receipt, signing_secret=signing_secret)

    def parse_omnibar_batch(
        self,
        *,
        inputs: List[str],
        now: Optional[str] = None,
        timezone: Optional[str] = None,
        default_currency: Optional[str] = None,
        locale: Optional[str] = None,
        last_answer: Optional[float] = None,
        user_weight_kg: Optional[float] = None,
        fx_rates: Optional[Dict[str, float]] = None,
        domains: Optional[List[str]] = None,
        projects: Optional[List[Dict[str, Any]]] = None,
        custom_routes: Optional[List[Dict[str, Any]]] = None,
        macros: Optional[Dict[str, str]] = None,
        wake_words: Optional[List[str]] = None,
        snapshot: Optional[Dict[str, Any]] = None,
        previous_intent: Optional[Dict[str, Any]] = None,
        custom_foods: Optional[List[Dict[str, Any]]] = None,
        custom_slash_commands: Optional[List[Dict[str, Any]]] = None,
        allow_compound: Optional[bool] = None,
        include_tokens: Optional[bool] = None,
        include_spans: Optional[bool] = None,
        include_alternatives: Optional[bool] = None,
        include_sentiment: Optional[bool] = None,
        include_ics: Optional[bool] = None,
        receipt: Optional[bool] = None,
        signing_secret: Optional[str] = None,
    ) -> Dict[str, Any]:
        """43 — Stateless Sequential Omnibar Batch Parser (`POST /v1/omnibar/batch`)."""
        payload: Dict[str, Any] = {"inputs": inputs}
        for key, value in (
            ("now", now),
            ("timezone", timezone),
            ("default_currency", default_currency),
            ("locale", locale),
            ("last_answer", last_answer),
            ("user_weight_kg", user_weight_kg),
            ("fx_rates", fx_rates),
            ("domains", domains),
            ("projects", projects),
            ("custom_routes", custom_routes),
            ("macros", macros),
            ("wake_words", wake_words),
            ("snapshot", snapshot),
            ("previous_intent", previous_intent),
            ("custom_foods", custom_foods),
            ("custom_slash_commands", custom_slash_commands),
            ("allow_compound", allow_compound),
            ("include_tokens", include_tokens),
            ("include_spans", include_spans),
            ("include_alternatives", include_alternatives),
            ("include_sentiment", include_sentiment),
            ("include_ics", include_ics),
        ):
            if value is not None:
                payload[key] = value
        return self.call("/v1/omnibar/batch", payload, receipt=receipt, signing_secret=signing_secret)

    def list_omnibar_intents(self) -> Dict[str, Any]:
        """43 — List all 46 supported Omnibar NLP intents (`GET /v1/omnibar/intents`)."""
        return self._request("GET", "/v1/omnibar/intents")

    def estimate_nutrition(
        self,
        *,
        text: str,
        servings: Optional[int] = None,
        custom_foods: Optional[List[Dict[str, Any]]] = None,
        receipt: Optional[bool] = None,
        signing_secret: Optional[str] = None,
    ) -> Dict[str, Any]:
        """44 — Offline Natural-Language Meal Nutrition & Macros API (`POST /v1/nutrition/estimate`)."""
        payload: Dict[str, Any] = {"text": text}
        if servings is not None:
            payload["servings"] = servings
        if custom_foods is not None:
            payload["custom_foods"] = custom_foods
        return self.call("/v1/nutrition/estimate", payload, receipt=receipt, signing_secret=signing_secret)

    def estimate_calories_burned(
        self,
        *,
        activity: str,
        duration_minutes: Optional[float] = None,
        weight_kg: Optional[float] = None,
        receipt: Optional[bool] = None,
        signing_secret: Optional[str] = None,
    ) -> Dict[str, Any]:
        """44 — Offline Compendium MET Calories Burned API (`POST /v1/nutrition/calories-burned`)."""
        payload: Dict[str, Any] = {"activity": activity}
        if duration_minutes is not None:
            payload["duration_minutes"] = duration_minutes
        if weight_kg is not None:
            payload["weight_kg"] = weight_kg
        return self.call("/v1/nutrition/calories-burned", payload, receipt=receipt, signing_secret=signing_secret)

    def calculate_nutrition_targets(
        self,
        *,
        weight_kg: Optional[float] = None,
        height_cm: Optional[float] = None,
        age_years: Optional[int] = None,
        sex: Optional[str] = None,
        activity_level: Optional[str] = None,
        goal: Optional[str] = None,
        target_calories: Optional[float] = None,
        receipt: Optional[bool] = None,
        signing_secret: Optional[str] = None,
    ) -> Dict[str, Any]:
        """44 — Offline Mifflin-St Jeor BMR/TDEE, Macro Split & Hydration Target Coach (`POST /v1/nutrition/targets`)."""
        payload: Dict[str, Any] = {}
        for key, value in (
            ("weight_kg", weight_kg),
            ("height_cm", height_cm),
            ("age_years", age_years),
            ("sex", sex),
            ("activity_level", activity_level),
            ("goal", goal),
            ("target_calories", target_calories),
        ):
            if value is not None:
                payload[key] = value
        return self.call("/v1/nutrition/targets", payload, receipt=receipt, signing_secret=signing_secret)

    def guard_llm_turn(
        self,
        *,
        user_prompt: str,
        generate: Callable[[str], str],
        locales: Optional[List[str]] = None,
        sensitivity: str = "medium",
        block_on_review: bool = False,
        block_on_flag: bool = False,
    ) -> Dict[str, Any]:
        """Run Prompt Guard + PII Redactor before `generate`, then guard LLM output."""
        should_block_review = block_on_review or block_on_flag
        pre = self.pipeline([
            {
                "id": "prompt",
                "endpoint": "/v1/prompt-guard",
                "body": {"text": user_prompt, "context": "user_input", "sensitivity": sensitivity},
            },
            {
                "id": "pii",
                "endpoint": "/v1/pii-redactor",
                "body": {"text": user_prompt, "locales": locales or ["GLOBAL"], "mode": "token"},
            },
        ])
        blocked, verdict, redacted_prompt = _validate_input_guardrail_pipeline(
            pre,
            prompt_id="prompt",
            pii_id="pii",
            block_on_review=should_block_review,
        )

        if blocked:
            return {"blocked": True, "verdict": verdict, "redacted_prompt": redacted_prompt, "output": None}

        raw_output = generate(redacted_prompt)
        out_res = self.guard_llm_output(output=raw_output)
        out_data = out_res.get("data")
        if not isinstance(out_data, dict):
            raise TinplateError(502, "guardrail_failed", "Output guardrail returned invalid data")
        out_verdict = out_data.get("verdict")
        output_blocked = _is_output_blocked(out_data, block_on_review=should_block_review)
        safe_output: Optional[str] = None
        if not output_blocked:
            if out_verdict == "sanitize" and isinstance(out_data.get("sanitized_output"), str):
                safe_output = out_data["sanitized_output"]
            else:
                safe_output = raw_output
        return {
            "blocked": output_blocked,
            "verdict": str(out_verdict) if (output_blocked or out_verdict == "sanitize") and isinstance(out_verdict, str) else verdict,
            "redacted_prompt": redacted_prompt,
            "output": safe_output,
            "output_guard": out_data,
        }
