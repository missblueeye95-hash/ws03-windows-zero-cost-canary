from __future__ import annotations

import base64
from hashlib import sha256
import json
import os
import re
import time
from urllib.error import HTTPError
from urllib.parse import quote, urlencode, urlparse
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

AUDIENCE = 'ws03-private-control-plane'
SESSION_RE = re.compile(r'^[A-Za-z0-9._:-]{1,160}$')


def _json_request(method: str, url: str, body=None, *, headers=None, timeout=20):
    payload = None
    merged = {'Accept': 'application/json'}
    if headers:
        merged.update(headers)
    if body is not None:
        payload = json.dumps(body, separators=(',', ':')).encode('utf-8')
        merged['Content-Type'] = 'application/json'
    request = Request(url, data=payload, headers=merged, method=method)
    with urlopen(request, timeout=timeout) as response:
        raw = response.read()
    value = json.loads(raw.decode('utf-8'))
    if not isinstance(value, dict):
        raise RuntimeError('endpoint response root is not an object')
    return value


def _post(path: str, body: dict):
    return _json_request('POST', ENDPOINT + path, body)


def _expect_conflict(path: str, body: dict):
    try:
        _post(path, body)
    except HTTPError as exc:
        if exc.code != 409:
            raise RuntimeError(f'expected HTTP 409 replay rejection, received {exc.code}') from exc
        return
    raise RuntimeError('expected replay rejection but request succeeded')


def _envelope(value: dict):
    return (
        base64.b64decode(value['nonce_b64'], validate=True),
        base64.b64decode(value['ciphertext_b64'], validate=True),
    )


def _request_oidc_token() -> str:
    request_url = os.environ['ACTIONS_ID_TOKEN_REQUEST_URL']
    request_token = os.environ['ACTIONS_ID_TOKEN_REQUEST_TOKEN']
    separator = '&' if '?' in request_url else '?'
    url = request_url + separator + 'audience=' + quote(AUDIENCE, safe='')
    value = _json_request(
        'GET',
        url,
        headers={'Authorization': 'Bearer ' + request_token},
    )
    token = value.get('value')
    if not isinstance(token, str) or token.count('.') != 2:
        raise RuntimeError('GitHub OIDC response did not contain a JWT')
    return token


def _poll_input():
    query = urlencode({'session_id': SESSION})
    deadline = time.time() + 300
    while time.time() < deadline:
        try:
            return _json_request('GET', ENDPOINT + '/v1/input?' + query)
        except HTTPError as exc:
            if exc.code not in (404, 409):
                raise
            time.sleep(2)
    raise RuntimeError('private canary endpoint did not become bound within 300 seconds')


ENDPOINT = os.environ['WS03_ENDPOINT_URL'].rstrip('/')
SESSION = os.environ['WS03_SESSION_ID']
parsed = urlparse(ENDPOINT)
if parsed.scheme != 'https' or not parsed.netloc or parsed.query or parsed.fragment:
    raise RuntimeError('WS03 endpoint must be a clean HTTPS origin')
if not SESSION_RE.fullmatch(SESSION):
    raise RuntimeError('WS03 session id is invalid')

input_bundle = _poll_input()
oidc_token = _request_oidc_token()
private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
public_pem = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)
release_body = {
    'session_id': SESSION,
    'oidc_token': oidc_token,
    'runner_public_key_pem_b64': base64.b64encode(public_pem).decode('ascii'),
}
release = _post('/v1/release', release_body)
wrap_aad = base64.b64decode(release['wrap_aad_b64'], validate=True)
wrapped_key = base64.b64decode(release['wrapped_data_key_b64'], validate=True)
data_key = bytearray(
    private_key.decrypt(
        wrapped_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=sha256(wrap_aad).digest(),
        ),
    )
)
if len(data_key) != 32:
    raise RuntimeError('released AES-256 key length is invalid')

input_nonce, input_ciphertext = _envelope(input_bundle['input_envelope'])
input_aad = base64.b64decode(input_bundle['input_aad_b64'], validate=True)
output_aad = base64.b64decode(input_bundle['output_aad_b64'], validate=True)
plaintext = bytearray(AESGCM(bytes(data_key)).decrypt(input_nonce, input_ciphertext, input_aad))
result_plaintext = bytearray(
    b'WS03-PRIVATE-LIVE-RESULT:' + sha256(bytes(plaintext)).hexdigest().encode('ascii')
)
result_nonce = os.urandom(12)
result_ciphertext = AESGCM(bytes(data_key)).encrypt(
    result_nonce,
    bytes(result_plaintext),
    output_aad,
)
output_envelope = {
    'schema_version': 1,
    'algorithm': 'AES-256-GCM',
    'nonce_b64': base64.b64encode(result_nonce).decode('ascii'),
    'ciphertext_b64': base64.b64encode(result_ciphertext).decode('ascii'),
    'aad_sha256': sha256(output_aad).hexdigest(),
    'ciphertext_sha256': sha256(result_ciphertext).hexdigest(),
}
result_body = {
    'session_id': SESSION,
    'oidc_token': oidc_token,
    'runner_public_key_sha256': release['runner_public_key_sha256'],
    'output_envelope': output_envelope,
}
result = _post('/v1/result', result_body)
expected_result_digest = sha256(bytes(result_plaintext)).hexdigest()
if result.get('result_plaintext_sha256') != expected_result_digest:
    raise RuntimeError('endpoint result plaintext digest does not match runner result')

# Exercise both one-shot guards before cleanup. These calls must not succeed.
_expect_conflict('/v1/release', release_body)
_expect_conflict('/v1/result', result_body)

for buffer in (plaintext, result_plaintext, data_key):
    for index in range(len(buffer)):
        buffer[index] = 0
private_key = None
wrapped_key = b''
wrap_aad = b''
input_ciphertext = b''
result_ciphertext = b''

cleanup = _post(
    '/v1/cleanup',
    {
        'session_id': SESSION,
        'oidc_token': oidc_token,
        'runner_public_key_sha256': release['runner_public_key_sha256'],
        'decrypted_files_remaining': 0,
        'temporary_key_files_remaining': 0,
    },
)
oidc_token = None

print('WS03_PRIVATE_LIVE=PASS')
print('WS03_PRIVATE_INPUT_CIPHERTEXT_SHA256=' + input_bundle['input_envelope']['ciphertext_sha256'])
print('WS03_PRIVATE_OUTPUT_CIPHERTEXT_SHA256=' + output_envelope['ciphertext_sha256'])
print('WS03_PRIVATE_RESULT_RECEIPT_SHA256=' + result['receipt_sha256'])
print('WS03_PRIVATE_CLEANUP_RECEIPT_SHA256=' + cleanup['receipt_sha256'])
print('WS03_PRIVATE_RESULT_PLAINTEXT_SHA256=' + expected_result_digest)
