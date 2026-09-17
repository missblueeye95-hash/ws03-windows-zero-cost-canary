from __future__ import annotations

import base64
from collections import namedtuple
from hashlib import sha256
import hmac
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import time
from typing import Any
from urllib.error import HTTPError
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


Envelope = namedtuple(
    "Envelope",
    "schema_version algorithm nonce ciphertext aad_sha256 ciphertext_sha256",
)
SessionCommandFrame = namedtuple(
    "SessionCommandFrame",
    "session_id sequence operation_id action envelope",
)
SessionResultFrame = namedtuple(
    "SessionResultFrame",
    "session_id sequence operation_id action envelope",
)
ScreenshotFrame = namedtuple("ScreenshotFrame", "data width height mime_type", defaults=["image/png"])

_ALLOWED_ACTIONS = {
    "exec",
    "put_file",
    "get_file",
    "computer_start",
    "computer_screenshot",
    "computer_click",
    "computer_type",
    "computer_stop",
    "stop_session",
    "destroy_session",
}
_MAX_FILE_BYTES = 8 * 1024 * 1024
_AUDIENCE = "ws03-private-control-plane"
_SESSION_RE = __import__("re").compile(r"^ws03-session-[A-Za-z0-9._:-]{1,128}$")
_SHA256_RE = __import__("re").compile(r"^[0-9a-f]{64}$")


def _canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _aad(session_id: str, direction: str, sequence: int, operation_id: str, action: str) -> bytes:
    return _canonical_json(
        {
            "action": action,
            "direction": direction,
            "operation_id": operation_id,
            "protocol": "ws03-github-windows-session-v1",
            "sequence": sequence,
            "session_id": session_id,
        }
    )


def session_request_mac(
    data_key: bytes,
    session_id: str,
    method: str,
    path: str,
    sequence: int,
    body: bytes,
) -> str:
    if not isinstance(data_key, bytes) or len(data_key) != 32:
        raise ValueError("session MAC key must be exactly 32 bytes")
    if not isinstance(body, bytes):
        raise ValueError("session MAC body must be bytes")
    material = _canonical_json(
        {
            "body_sha256": sha256(body).hexdigest(),
            "method": method.upper(),
            "path": path,
            "protocol": "ws03-github-windows-session-v1",
            "sequence": sequence,
            "session_id": session_id,
        }
    )
    return hmac.new(data_key, material, sha256).hexdigest()


def _decrypt(envelope: object, data_key: bytes, aad: bytes) -> bytes:
    if getattr(envelope, "schema_version", None) != 1:
        raise ValueError("session envelope schema mismatch")
    if getattr(envelope, "algorithm", None) != "AES-256-GCM":
        raise ValueError("session envelope algorithm mismatch")
    nonce = bytes(getattr(envelope, "nonce", b""))
    ciphertext = bytes(getattr(envelope, "ciphertext", b""))
    if len(nonce) != 12:
        raise ValueError("session envelope nonce mismatch")
    if getattr(envelope, "aad_sha256", None) != sha256(aad).hexdigest():
        raise ValueError("session envelope AAD mismatch")
    if getattr(envelope, "ciphertext_sha256", None) != sha256(ciphertext).hexdigest():
        raise ValueError("session envelope ciphertext hash mismatch")
    try:
        return AESGCM(data_key).decrypt(nonce, ciphertext, aad)
    except Exception as exc:
        raise ValueError("session envelope authentication failed") from exc


def _encrypt(plaintext: bytes, data_key: bytes, aad: bytes) -> Envelope:
    nonce = os.urandom(12)
    ciphertext = AESGCM(data_key).encrypt(nonce, plaintext, aad)
    return Envelope(
        1,
        "AES-256-GCM",
        nonce,
        ciphertext,
        sha256(aad).hexdigest(),
        sha256(ciphertext).hexdigest(),
    )


def _default_executor(argv, timeout_seconds, cwd):
    if not isinstance(argv, (list, tuple)) or not argv or any(
        not isinstance(value, str) or not value for value in argv
    ):
        raise ValueError("exec argv must contain non-empty strings")
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 300:
        raise ValueError("exec timeout must be in 1..300 seconds")
    try:
        completed = subprocess.run(
            list(argv),
            cwd=str(cwd),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError("worker exec timed out after possible effect") from exc
    return int(completed.returncode), completed.stdout.decode("utf-8", "replace")


def _utf16_code_units(text):
    if not isinstance(text, str):
        raise ValueError("typed text must be text")
    encoded = text.encode("utf-16-le")
    return [int.from_bytes(encoded[index : index + 2], "little") for index in range(0, len(encoded), 2)]


def _windows_input_types():
    import ctypes
    from ctypes import wintypes

    ULONG_PTR = wintypes.WPARAM

    class MOUSEINPUT(ctypes.Structure):
        _fields_ = [
            ("dx", wintypes.LONG),
            ("dy", wintypes.LONG),
            ("mouseData", wintypes.DWORD),
            ("dwFlags", wintypes.DWORD),
            ("time", wintypes.DWORD),
            ("dwExtraInfo", ULONG_PTR),
        ]

    class KEYBDINPUT(ctypes.Structure):
        _fields_ = [
            ("wVk", wintypes.WORD),
            ("wScan", wintypes.WORD),
            ("dwFlags", wintypes.DWORD),
            ("time", wintypes.DWORD),
            ("dwExtraInfo", ULONG_PTR),
        ]

    class HARDWAREINPUT(ctypes.Structure):
        _fields_ = [
            ("uMsg", wintypes.DWORD),
            ("wParamL", wintypes.WORD),
            ("wParamH", wintypes.WORD),
        ]

    class INPUT_UNION(ctypes.Union):
        _fields_ = [("mi", MOUSEINPUT), ("ki", KEYBDINPUT), ("hi", HARDWAREINPUT)]

    class INPUT(ctypes.Structure):
        _fields_ = [("type", wintypes.DWORD), ("u", INPUT_UNION)]

    return KEYBDINPUT, INPUT


class WindowsComputer:
    def _require_windows(self):
        if os.name != "nt":
            raise ValueError("computer use requires Windows")

    def start(self):
        self._require_windows()

    def ready_probe(self):
        self._require_windows()
        script = r'''
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class Ws03DesktopNative {
  [DllImport("user32.dll", SetLastError=true)] public static extern IntPtr OpenInputDesktop(uint flags, bool inherit, uint access);
  [DllImport("user32.dll", SetLastError=true)] public static extern bool CloseDesktop(IntPtr desktop);
}
"@
$desktop=[Ws03DesktopNative]::OpenInputDesktop(0,$false,1)
$opened=$desktop -ne [IntPtr]::Zero
if ($opened) { [void][Ws03DesktopNative]::CloseDesktop($desktop) }
$b=[System.Windows.Forms.Screen]::PrimaryScreen.Bounds
$bmp=New-Object System.Drawing.Bitmap $b.Width,$b.Height
$g=[System.Drawing.Graphics]::FromImage($bmp)
$g.CopyFromScreen($b.Location,[System.Drawing.Point]::Empty,$b.Size)
$points=@(
  @(0,0),@([Math]::Max(0,$b.Width-1),0),@(0,[Math]::Max(0,$b.Height-1)),
  @([Math]::Floor($b.Width/2),[Math]::Floor($b.Height/2)),
  @([Math]::Floor($b.Width/4),[Math]::Floor($b.Height/4)),
  @([Math]::Floor(3*$b.Width/4),[Math]::Floor(3*$b.Height/4))
)
$values=@()
foreach($p in $points){ $values += $bmp.GetPixel([int]$p[0],[int]$p[1]).ToArgb() }
$ms=New-Object System.IO.MemoryStream
$bmp.Save($ms,[System.Drawing.Imaging.ImageFormat]::Png)
$bytes=$ms.ToArray()
$sha=[System.Security.Cryptography.SHA256]::Create()
$hash=([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()
$sha.Dispose(); $ms.Dispose(); $g.Dispose(); $bmp.Dispose()
[pscustomobject]@{
 user_interactive=[Environment]::UserInteractive
 input_desktop_opened=$opened
 screenshot_captured=($bytes.Length -gt 0)
 screenshot_non_uniform=(($values | Select-Object -Unique).Count -gt 1)
 screenshot_sha256=$hash
 screenshot_width=$b.Width
 screenshot_height=$b.Height
} | ConvertTo-Json -Compress
'''
        completed = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )
        if completed.returncode != 0:
            raise ValueError("desktop readiness probe failed")
        try:
            value = json.loads(completed.stdout.decode("utf-8"))
        except Exception as exc:
            raise ValueError("desktop readiness probe returned invalid JSON") from exc
        if not isinstance(value, dict):
            raise ValueError("desktop readiness probe returned invalid object")
        return value

    def screenshot(self):
        self._require_windows()
        script = r'''
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$b=[System.Windows.Forms.Screen]::PrimaryScreen.Bounds
$bmp=New-Object System.Drawing.Bitmap $b.Width,$b.Height
$g=[System.Drawing.Graphics]::FromImage($bmp)
$g.CopyFromScreen($b.Location,[System.Drawing.Point]::Empty,$b.Size)
$ms=New-Object System.IO.MemoryStream
$bmp.Save($ms,[System.Drawing.Imaging.ImageFormat]::Png)
$g.Dispose(); $bmp.Dispose()
[Console]::Out.Write(([Convert]::ToBase64String($ms.ToArray()))+'|'+$b.Width+'|'+$b.Height)
$ms.Dispose()
'''
        completed = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )
        if completed.returncode != 0:
            raise ValueError("screenshot capture failed")
        encoded, width, height = completed.stdout.decode("ascii").split("|", 2)
        return ScreenshotFrame(base64.b64decode(encoded), int(width), int(height), "image/png")

    def click(self, x, y, button, double):
        self._require_windows()
        if button != "left":
            raise ValueError("session worker currently supports left click only")
        import ctypes
        from ctypes import wintypes

        user32 = ctypes.WinDLL("user32", use_last_error=True)
        if not user32.SetCursorPos(int(x), int(y)):
            raise ValueError("SetCursorPos failed")
        MOUSEEVENTF_LEFTDOWN = 0x0002
        MOUSEEVENTF_LEFTUP = 0x0004
        count = 2 if bool(double) else 1
        for _ in range(count):
            user32.mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0)
            user32.mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0)

    def type(self, text, delay_ms):
        self._require_windows()
        import ctypes
        import time
        from ctypes import wintypes

        KEYBDINPUT, INPUT = _windows_input_types()
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        user32.SendInput.argtypes = (wintypes.UINT, ctypes.POINTER(INPUT), ctypes.c_int)
        user32.SendInput.restype = wintypes.UINT
        KEYEVENTF_UNICODE = 0x0004
        KEYEVENTF_KEYUP = 0x0002

        for code in _utf16_code_units(text):
            inputs = (INPUT * 2)()
            inputs[0].type = 1
            inputs[0].u.ki = KEYBDINPUT(0, code, KEYEVENTF_UNICODE, 0, 0)
            inputs[1].type = 1
            inputs[1].u.ki = KEYBDINPUT(0, code, KEYEVENTF_UNICODE | KEYEVENTF_KEYUP, 0, 0)
            sent = user32.SendInput(2, inputs, ctypes.sizeof(INPUT))
            if sent != 2:
                error = ctypes.get_last_error()
                raise ValueError(f"SendInput unicode delivery failed: winerror={error}")
            if delay_ms:
                time.sleep(max(0, int(delay_ms)) / 1000.0)

    def stop(self):
        self._require_windows()


class WorkerEngine:
    def __init__(
        self,
        *,
        session_id: str,
        data_key: bytes,
        workspace: Path,
        executor=None,
        computer=None,
    ) -> None:
        if not isinstance(session_id, str) or not session_id.startswith("ws03-session-"):
            raise ValueError("invalid worker session id")
        if not isinstance(data_key, bytes) or len(data_key) != 32:
            raise ValueError("worker data key must be exactly 32 bytes")
        self.session_id = session_id
        self._data_key = bytearray(data_key)
        self.workspace = Path(workspace).resolve()
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.executor = executor or _default_executor
        self.computer = computer or WindowsComputer()
        self.state = "running"
        self._cache: dict[str, tuple[str, SessionResultFrame]] = {}

    @staticmethod
    def _fingerprint(frame: object) -> str:
        envelope = getattr(frame, "envelope", None)
        material = {
            "action": getattr(frame, "action", None),
            "ciphertext_sha256": getattr(envelope, "ciphertext_sha256", None),
            "operation_id": getattr(frame, "operation_id", None),
            "sequence": getattr(frame, "sequence", None),
            "session_id": getattr(frame, "session_id", None),
        }
        return sha256(_canonical_json(material)).hexdigest()

    def _safe_path(self, value: str) -> Path:
        if not isinstance(value, str) or not value:
            raise ValueError("remote path must be non-empty text")
        normalized = value.replace("\\", "/")
        posix = PurePosixPath(normalized)
        if posix.is_absolute() or any(part in {"", ".", ".."} for part in posix.parts):
            raise ValueError("remote path traversal is forbidden")
        if any(":" in part for part in posix.parts):
            raise ValueError("remote path drive syntax is forbidden")
        target = self.workspace.joinpath(*posix.parts).resolve()
        try:
            target.relative_to(self.workspace)
        except ValueError as exc:
            raise ValueError("remote path escapes workspace") from exc
        return target

    def _handle_action(self, action: str, payload: dict[str, Any]) -> dict[str, Any]:
        if action not in _ALLOWED_ACTIONS:
            raise ValueError("unsupported session action")
        if self.state == "destroyed":
            raise ValueError("session worker is destroyed")
        if self.state == "stopped" and action != "destroy_session":
            raise ValueError("session worker is stopped")

        if action == "exec":
            argv = payload.get("argv")
            timeout_seconds = payload.get("timeout_seconds")
            exit_code, output = self.executor(argv, timeout_seconds, self.workspace)
            return {"exit_code": int(exit_code), "output": str(output)}

        if action == "put_file":
            target = self._safe_path(payload.get("path"))
            try:
                data = base64.b64decode(payload.get("data_b64"), validate=True)
            except Exception as exc:
                raise ValueError("put_file data is invalid base64") from exc
            if len(data) > _MAX_FILE_BYTES:
                raise ValueError("put_file exceeds session file limit")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            return {"bytes_written": len(data), "sha256": sha256(data).hexdigest()}

        if action == "get_file":
            target = self._safe_path(payload.get("path"))
            if not target.is_file():
                raise ValueError("get_file target is missing")
            data = target.read_bytes()
            if len(data) > _MAX_FILE_BYTES:
                raise ValueError("get_file exceeds session file limit")
            return {
                "data_b64": base64.b64encode(data).decode("ascii"),
                "bytes": len(data),
                "sha256": sha256(data).hexdigest(),
            }

        if action == "computer_start":
            self.computer.start()
            return {"started": True}

        if action == "computer_screenshot":
            frame = self.computer.screenshot()
            return {
                "data_b64": base64.b64encode(bytes(frame.data)).decode("ascii"),
                "width": int(frame.width),
                "height": int(frame.height),
                "mime_type": str(getattr(frame, "mime_type", "image/png")),
            }

        if action == "computer_click":
            self.computer.click(
                int(payload.get("x")),
                int(payload.get("y")),
                str(payload.get("button")),
                bool(payload.get("double")),
            )
            return {"clicked": True}

        if action == "computer_type":
            self.computer.type(payload.get("text"), payload.get("delay_ms"))
            return {"typed": True}

        if action == "computer_stop":
            self.computer.stop()
            return {"stopped": True}

        if action == "stop_session":
            self.state = "stopped"
            return {"state": "stopped"}

        if action == "destroy_session":
            for child in list(self.workspace.iterdir()):
                if child.is_dir():
                    shutil.rmtree(child)
                else:
                    child.unlink()
            self.state = "destroyed"
            return {
                "decrypted_files_remaining": sum(1 for p in self.workspace.rglob("*") if p.is_file()),
                "temporary_key_files_remaining": 0,
                "state": "destroyed",
            }

        raise ValueError("unsupported session action")

    def handle(self, frame: object) -> SessionResultFrame:
        if getattr(frame, "session_id", None) != self.session_id:
            raise ValueError("session command identity mismatch")
        operation_id = getattr(frame, "operation_id", None)
        action = getattr(frame, "action", None)
        sequence = getattr(frame, "sequence", None)
        if not isinstance(operation_id, str) or not operation_id:
            raise ValueError("session command operation id is invalid")
        if type(sequence) is not int or sequence <= 0:
            raise ValueError("session command sequence is invalid")
        fingerprint = self._fingerprint(frame)
        cached = self._cache.get(operation_id)
        if cached is not None:
            previous_fingerprint, previous_result = cached
            if previous_fingerprint != fingerprint:
                raise ValueError("session operation replay conflicts with prior command")
            return previous_result
        if self.state == "destroyed":
            raise ValueError("session worker is destroyed")
        aad = _aad(self.session_id, "command", sequence, operation_id, action)
        plaintext = _decrypt(getattr(frame, "envelope", None), bytes(self._data_key), aad)
        try:
            command = json.loads(plaintext.decode("utf-8"))
        except Exception as exc:
            raise ValueError("session command JSON is invalid") from exc
        if not isinstance(command, dict) or command.get("schema_version") != 1:
            raise ValueError("session command schema is invalid")
        if (
            command.get("session_id") != self.session_id
            or command.get("operation_id") != operation_id
            or command.get("action") != action
        ):
            raise ValueError("session command binding mismatch")
        payload = command.get("payload")
        if not isinstance(payload, dict):
            raise ValueError("session command payload must be an object")
        result = self._handle_action(action, payload)
        result_message = {
            "action": action,
            "operation_id": operation_id,
            "result": result,
            "schema_version": 1,
            "sequence": sequence,
            "session_id": self.session_id,
        }
        result_aad = _aad(self.session_id, "result", sequence, operation_id, action)
        result_envelope = _encrypt(
            _canonical_json(result_message),
            bytes(self._data_key),
            result_aad,
        )
        result_frame = SessionResultFrame(
            self.session_id,
            sequence,
            operation_id,
            action,
            result_envelope,
        )
        self._cache[operation_id] = (fingerprint, result_frame)
        if action == "destroy_session":
            for index in range(len(self._data_key)):
                self._data_key[index] = 0
        return result_frame


def _envelope_to_json(envelope):
    return {
        "schema_version": int(envelope.schema_version),
        "algorithm": str(envelope.algorithm),
        "nonce_b64": base64.b64encode(bytes(envelope.nonce)).decode("ascii"),
        "ciphertext_b64": base64.b64encode(bytes(envelope.ciphertext)).decode("ascii"),
        "aad_sha256": str(envelope.aad_sha256),
        "ciphertext_sha256": str(envelope.ciphertext_sha256),
    }


def _envelope_from_json(value):
    if not isinstance(value, dict):
        raise ValueError("session HTTP envelope must be an object")
    try:
        return Envelope(
            int(value["schema_version"]),
            str(value["algorithm"]),
            base64.b64decode(value["nonce_b64"], validate=True),
            base64.b64decode(value["ciphertext_b64"], validate=True),
            str(value["aad_sha256"]),
            str(value["ciphertext_sha256"]),
        )
    except Exception as exc:
        raise ValueError("session HTTP envelope is malformed") from exc


def _command_frame_from_json(value):
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise ValueError("session HTTP command frame schema is invalid")
    try:
        return SessionCommandFrame(
            str(value["session_id"]),
            int(value["sequence"]),
            str(value["operation_id"]),
            str(value["action"]),
            _envelope_from_json(value["envelope"]),
        )
    except Exception as exc:
        if isinstance(exc, ValueError):
            raise
        raise ValueError("session HTTP command frame is malformed") from exc


def _result_frame_to_json(frame):
    return {
        "schema_version": 1,
        "session_id": frame.session_id,
        "sequence": frame.sequence,
        "operation_id": frame.operation_id,
        "action": frame.action,
        "envelope": _envelope_to_json(frame.envelope),
    }


class WorkerPollClient:
    """Public worker dataplane client after the one-time OIDC/key-release bootstrap."""

    def __init__(self, *, session_id, data_key, transport, engine):
        if not isinstance(session_id, str) or not session_id.startswith("ws03-session-"):
            raise ValueError("invalid session poll client id")
        if not isinstance(data_key, bytes) or len(data_key) != 32:
            raise ValueError("session poll client data key must be exactly 32 bytes")
        if not callable(getattr(transport, "request", None)):
            raise ValueError("session poll client transport must expose request()")
        if not isinstance(engine, WorkerEngine):
            raise ValueError("session poll client requires WorkerEngine")
        self.session_id = session_id
        self._data_key = bytearray(data_key)
        self.transport = transport
        self.engine = engine
        self.last_sequence = 0
        self.finished = False
        self._pending_result = None

    def _key(self):
        return bytes(self._data_key)

    def _headers(self, method, path, sequence, body):
        return {
            "X-WS03-Session": self.session_id,
            "X-WS03-Sequence": str(sequence),
            "X-WS03-MAC": session_request_mac(
                self._key(), self.session_id, method, path, sequence, body
            ),
        }

    def _post_pending_result(self):
        if self._pending_result is None:
            return False
        frame, body = self._pending_result
        path = "/v1/result"
        headers = self._headers("POST", path, frame.sequence, body)
        status, _response_headers, response_body = self.transport.request(
            "POST", path, headers, body
        )
        if status != 200:
            raise ValueError(f"session result post failed with HTTP {status}")
        try:
            response = json.loads(response_body.decode("utf-8"))
        except Exception as exc:
            raise ValueError("session result response JSON is invalid") from exc
        if response.get("accepted") is not True:
            raise ValueError("session result was not accepted")
        self.last_sequence = frame.sequence
        self._pending_result = None
        if self.engine.state == "destroyed":
            self.finished = True
            for index in range(len(self._data_key)):
                self._data_key[index] = 0
        return True

    def poll_once(self):
        if self.finished:
            return False
        if self._pending_result is not None:
            return self._post_pending_result()

        path = f"/v1/command?after={self.last_sequence}"
        body = b""
        headers = self._headers("GET", path, self.last_sequence, body)
        status, _response_headers, response_body = self.transport.request(
            "GET", path, headers, body
        )
        if status == 204:
            return False
        if status != 200:
            raise ValueError(f"session command poll failed with HTTP {status}")
        try:
            command = _command_frame_from_json(json.loads(response_body.decode("utf-8")))
        except Exception as exc:
            if isinstance(exc, ValueError):
                raise
            raise ValueError("session command response JSON is invalid") from exc
        if command.session_id != self.session_id:
            raise ValueError("session command response identity mismatch")
        if command.sequence != self.last_sequence + 1:
            raise ValueError("session command sequence is not the next expected value")
        result_frame = self.engine.handle(command)
        result_body = _canonical_json(_result_frame_to_json(result_frame))
        self._pending_result = (result_frame, result_body)
        return self._post_pending_result()


class UrllibEndpointTransport:
    def __init__(self, endpoint):
        if not isinstance(endpoint, str):
            raise ValueError("session endpoint must be text")
        parsed = urlparse(endpoint)
        if parsed.scheme != "https" or not parsed.netloc or parsed.query or parsed.fragment:
            raise ValueError("session endpoint must be a clean HTTPS origin")
        self.endpoint = endpoint.rstrip("/")

    def request(self, method, path, headers, body):
        if not isinstance(path, str) or not path.startswith("/"):
            raise ValueError("session transport path must be absolute")
        merged = {"Accept": "application/json"}
        merged.update(dict(headers or {}))
        payload = bytes(body) if body else None
        if payload is not None:
            merged.setdefault("Content-Type", "application/json")
        request = Request(self.endpoint + path, data=payload, headers=merged, method=str(method).upper())
        try:
            with urlopen(request, timeout=30) as response:
                return int(response.status), dict(response.headers.items()), response.read()
        except HTTPError as exc:
            return int(exc.code), dict(exc.headers.items()) if exc.headers else {}, exc.read()


def request_oidc_token(env=None):
    env = os.environ if env is None else env
    request_url = env.get("ACTIONS_ID_TOKEN_REQUEST_URL")
    request_token = env.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if not isinstance(request_url, str) or not request_url or not isinstance(request_token, str) or not request_token:
        raise ValueError("GitHub OIDC request environment is unavailable")
    separator = "&" if "?" in request_url else "?"
    url = request_url + separator + "audience=" + quote(_AUDIENCE, safe="")
    request = Request(url, headers={"Accept": "application/json", "Authorization": "Bearer " + request_token}, method="GET")
    with urlopen(request, timeout=20) as response:
        raw = response.read()
    try:
        value = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise ValueError("GitHub OIDC response JSON is invalid") from exc
    token = value.get("value") if isinstance(value, dict) else None
    if not isinstance(token, str) or token.count(".") != 2:
        raise ValueError("GitHub OIDC response did not contain a JWT")
    return token


def bootstrap_session_key(*, transport, session_id, worker_sha256, oidc_token_provider=None):
    if not _SESSION_RE.fullmatch(session_id or ""):
        raise ValueError("bootstrap session id is invalid")
    if not _SHA256_RE.fullmatch(worker_sha256 or ""):
        raise ValueError("bootstrap worker hash is invalid")
    if not callable(getattr(transport, "request", None)):
        raise ValueError("bootstrap transport must expose request()")
    provider = oidc_token_provider or request_oidc_token
    token = provider()
    if not isinstance(token, str) or token.count(".") != 2:
        raise ValueError("bootstrap OIDC token is invalid")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    body = _canonical_json(
        {
            "session_id": session_id,
            "oidc_token": token,
            "runner_public_key_pem_b64": base64.b64encode(public_pem).decode("ascii"),
            "worker_sha256": worker_sha256,
        }
    )
    response_body = None
    last_error = None
    retryable_status = {408, 425, 429, 500, 502, 503, 504}
    for attempt in range(2):
        try:
            status, _headers, response_body = transport.request("POST", "/v1/bootstrap", {}, body)
        except (OSError, TimeoutError) as exc:
            last_error = exc
            if attempt == 0:
                continue
            raise ValueError("session bootstrap transport failed after exact retry") from exc
        if status == 200:
            break
        if status in retryable_status and attempt == 0:
            continue
        raise ValueError(f"session bootstrap failed with HTTP {status}")
    if response_body is None:
        raise ValueError("session bootstrap returned no response") from last_error
    try:
        response = json.loads(response_body.decode("utf-8"))
        if response.get("schema_version") != 1 or response.get("session_id") != session_id:
            raise ValueError("bootstrap response binding mismatch")
        if response.get("runner_public_key_sha256") != sha256(public_pem).hexdigest():
            raise ValueError("bootstrap runner key hash mismatch")
        wrap_aad = base64.b64decode(response["wrap_aad_b64"], validate=True)
        wrapped_key = base64.b64decode(response["wrapped_data_key_b64"], validate=True)
        data_key = private_key.decrypt(
            wrapped_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=sha256(wrap_aad).digest(),
            ),
        )
    except Exception as exc:
        if isinstance(exc, ValueError):
            raise
        raise ValueError("session bootstrap response is invalid") from exc
    if len(data_key) != 32:
        raise ValueError("session bootstrap did not release an AES-256 key")
    token = None
    private_key = None
    wrapped_key = b""
    wrap_aad = b""
    return bytes(data_key)


def post_ready(*, transport, session_id, data_key, worker_sha256, computer=None, env=None):
    env = os.environ if env is None else env
    computer = computer or WindowsComputer()
    probe = computer.ready_probe()
    if not isinstance(probe, dict):
        raise ValueError("desktop readiness probe must return an object")
    try:
        run_id = int(env.get("GITHUB_RUN_ID", ""))
        run_attempt = int(env.get("GITHUB_RUN_ATTEMPT", ""))
    except Exception as exc:
        raise ValueError("GitHub run identity environment is invalid") from exc
    body_value = {
        "schema_version": 1,
        "session_id": session_id,
        "run_id": run_id,
        "run_attempt": run_attempt,
        "worker_sha256": worker_sha256,
        "runner_environment": env.get("RUNNER_ENVIRONMENT"),
        "runner_os": env.get("RUNNER_OS"),
        "image_os": env.get("ImageOS") or env.get("IMAGE_OS") or "unknown",
        "user_interactive": probe.get("user_interactive") is True,
        "input_desktop_opened": probe.get("input_desktop_opened") is True,
        "screenshot_captured": probe.get("screenshot_captured") is True,
        "screenshot_non_uniform": probe.get("screenshot_non_uniform") is True,
        "screenshot_sha256": probe.get("screenshot_sha256"),
        "screenshot_width": probe.get("screenshot_width"),
        "screenshot_height": probe.get("screenshot_height"),
        "fresh_vm_verified": env.get("WS03_FRESH_VM_VERIFIED") == "true",
        "public_bundle_verified": env.get("WS03_PUBLIC_BUNDLE_VERIFIED") == "true",
        "zero_paid_features": env.get("WS03_ZERO_PAID_FEATURES") == "true",
    }
    body = _canonical_json(body_value)
    path = "/v1/ready"
    headers = {
        "X-WS03-Session": session_id,
        "X-WS03-Sequence": "0",
        "X-WS03-MAC": session_request_mac(data_key, session_id, "POST", path, 0, body),
    }
    status, _response_headers, response_body = transport.request("POST", path, headers, body)
    if status != 200:
        raise ValueError(f"session ready post failed with HTTP {status}")
    try:
        response = json.loads(response_body.decode("utf-8"))
    except Exception as exc:
        raise ValueError("session ready response JSON is invalid") from exc
    if response.get("accepted") is not True:
        raise ValueError("session ready evidence was not accepted")
    return body_value


def run_live_worker(*, env=None, transport=None, oidc_token_provider=None, computer=None, executor=None, sleep=time.sleep, clock=time.monotonic):
    env = os.environ if env is None else env
    endpoint = env.get("WS03_ENDPOINT_URL")
    session_id = env.get("WS03_SESSION_ID")
    worker_sha256 = env.get("WS03_WORKER_SHA256")
    try:
        ttl_seconds = int(env.get("WS03_TTL_SECONDS", ""))
    except Exception as exc:
        raise ValueError("session worker TTL is invalid") from exc
    if not isinstance(endpoint, str):
        raise ValueError("session worker endpoint is missing")
    if not _SESSION_RE.fullmatch(session_id or ""):
        raise ValueError("session worker id is invalid")
    if not _SHA256_RE.fullmatch(worker_sha256 or ""):
        raise ValueError("session worker hash is invalid")
    if not 30 <= ttl_seconds <= 1800:
        raise ValueError("session worker TTL must be in 30..1800 seconds")
    transport = transport or UrllibEndpointTransport(endpoint)
    data_key = bytearray(
        bootstrap_session_key(
            transport=transport,
            session_id=session_id,
            worker_sha256=worker_sha256,
            oidc_token_provider=oidc_token_provider,
        )
    )
    workspace_root = env.get("RUNNER_TEMP") or os.getcwd()
    workspace = Path(workspace_root) / ("ws03-" + session_id)
    engine = WorkerEngine(
        session_id=session_id,
        data_key=bytes(data_key),
        workspace=workspace,
        executor=executor,
        computer=computer,
    )
    post_ready(
        transport=transport,
        session_id=session_id,
        data_key=bytes(data_key),
        worker_sha256=worker_sha256,
        computer=computer or engine.computer,
        env=env,
    )
    client = WorkerPollClient(
        session_id=session_id,
        data_key=bytes(data_key),
        transport=transport,
        engine=engine,
    )
    for index in range(len(data_key)):
        data_key[index] = 0
    deadline = clock() + ttl_seconds
    while not client.finished and clock() < deadline:
        progressed = client.poll_once()
        if not progressed:
            sleep(0.25)
    if not client.finished:
        raise TimeoutError("session worker TTL expired before destroy")
    print("WS03_SESSION_WORKER=PASS")
    print("WS03_SESSION_SEQUENCE=" + str(client.last_sequence))
    return client.last_sequence


if __name__ == "__main__":
    run_live_worker()


__all__ = [
    "UrllibEndpointTransport",
    "bootstrap_session_key",
    "post_ready",
    "request_oidc_token",
    "run_live_worker",
    "WorkerEngine",
    "WorkerPollClient",
    "WindowsComputer",
    "session_request_mac",
]
