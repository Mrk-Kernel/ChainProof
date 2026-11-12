"""Minimal RFC 3161 Time-Stamp Protocol (TSP) client."""

import base64
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

# Digest algorithm OIDs
HASH_ALGORITHM_OIDS = {
    "sha256": "2.16.840.1.101.3.4.2.1",
    "sha3_256": "2.16.840.1.101.3.4.2.8",
}


def _encode_length(length):
    if length < 128:
        return bytes([length])
    num_bytes = (length.bit_length() + 7) // 8
    return bytes([0x80 | num_bytes]) + length.to_bytes(num_bytes, "big")


def _encode_tag(tag, content):
    return bytes([tag]) + _encode_length(len(content)) + content


def _encode_oid(dotted_oid):
    parts = [int(x) for x in dotted_oid.split(".")]
    first = parts[0] * 40 + parts[1]
    content = bytes([first]) + bytes(parts[2:])
    return _encode_tag(0x06, content)


def _encode_integer(value):
    content = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big", signed=False)
    if content[0] & 0x80:
        content = b"\x00" + content
    return _encode_tag(0x02, content)


def _encode_octet_string(data):
    return _encode_tag(0x04, bytes(data))


def _encode_null():
    return bytes([0x05, 0x00])


def _encode_boolean(value):
    return _encode_tag(0x01, b"\xff" if value else b"\x00")


def _encode_context(tag, content, constructed=False):
    tag_byte = 0xA0 | tag
    if constructed:
        tag_byte |= 0x20
    return _encode_tag(tag_byte, content)


def build_timestamp_request(hash_hex, algorithm="sha256", cert_req=True):
    """Build a DER-encoded TimeStampReq (RFC 3161)."""
    oid = HASH_ALGORITHM_OIDS[algorithm]
    hashed = bytes.fromhex(hash_hex)

    message_imprint = _encode_tag(
        0x30,
        _encode_tag(0x30, _encode_oid(oid) + _encode_null())
        + _encode_octet_string(hashed),
    )

    import os
    nonce = _encode_context(1, _encode_integer(int.from_bytes(os.urandom(8), "big")))
    cert_req_enc = _encode_context(2, _encode_boolean(cert_req))

    version = _encode_integer(1)
    return _encode_tag(0x30, version + message_imprint + nonce + cert_req_enc)


class _DerReader:
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def read_tlv(self):
        tag = self.data[self.pos]
        self.pos += 1
        length = self.data[self.pos]
        self.pos += 1
        if length & 0x80:
            count = length & 0x7F
            length = int.from_bytes(self.data[self.pos:self.pos + count], "big")
            self.pos += count
        value = self.data[self.pos:self.pos + length]
        self.pos += length
        return tag, value

    def read_sequence(self):
        tag, value = self.read_tlv()
        if tag != 0x30:
            raise ValueError(f"Expected SEQUENCE, got tag 0x{tag:02x}")
        return _DerReader(value)

    def read_integer(self):
        tag, value = self.read_tlv()
        if tag != 0x02:
            raise ValueError(f"Expected INTEGER, got tag 0x{tag:02x}")
        return int.from_bytes(value, "big", signed=False)

    def read_oid(self):
        tag, value = self.read_tlv()
        if tag != 0x06:
            raise ValueError(f"Expected OID, got tag 0x{tag:02x}")
        return value

    def read_octet_string(self):
        tag, value = self.read_tlv()
        if tag != 0x04:
            raise ValueError(f"Expected OCTET STRING, got tag 0x{tag:02x}")
        return value

    def peek_tag(self):
        return self.data[self.pos]

    def at_end(self):
        return self.pos >= len(self.data)


class TimestampClient:
    def __init__(self, tsa_url=None, timeout=15):
        self.tsa_url = tsa_url
        self.timeout = timeout

    def request(self, hash_hex, algorithm="sha256"):
        """Contact a TSA and return {status, status_string, token_b64}.

        If no TSA URL is configured, returns status=None with no token.
        """
        if not self.tsa_url:
            return {"status": None, "status_string": "no TSA configured", "token_b64": None}

        der = build_timestamp_request(hash_hex, algorithm)
        req = Request(
            self.tsa_url,
            data=der,
            headers={"Content-Type": "application/timestamp-query"},
            method="POST",
        )
        try:
            with urlopen(req, timeout=self.timeout) as resp:
                body = resp.read()
                content_type = resp.headers.get("Content-Type", "")
        except HTTPError as exc:
            body = exc.read()
            content_type = exc.headers.get("Content-Type", "") if exc.headers else ""
        except URLError as exc:
            return {"status": -1, "status_string": f"TSA unreachable: {exc}", "token_b64": None}

        if "application/timestamp-reply" not in content_type:
            text = body.decode("utf-8", errors="replace")[:200]
            return {"status": -2, "status_string": f"unexpected response: {text}", "token_b64": None}

        return self._parse_response(body)

    def _parse_response(self, body):
        try:
            outer = _DerReader(body).read_sequence()
            status_info = outer.read_sequence()
            status_int = status_info.read_integer()

            # Consume optional statusString [0] / failInfo [1] inside PKIStatusInfo.
            while not status_info.at_end():
                tag = status_info.peek_tag()
                if tag in (0xA0, 0xA1):
                    status_info.read_tlv()
                else:
                    break

            token_b64 = None
            if not outer.at_end() and outer.peek_tag() == 0xA0:
                _, token_der = outer.read_tlv()
                token_b64 = base64.b64encode(token_der).decode("ascii")

            status_text = {0: "accepted", 2: "rejected", 3: "waiting"}.get(
                status_int, f"unknown({status_int})"
            )
            return {"status": status_int, "status_string": status_text, "token_b64": token_b64}
        except Exception as exc:  # noqa: BLE001 - parse failures degrade gracefully
            return {"status": -3, "status_string": f"parse error: {exc}", "token_b64": None}
