"""
create_test_apk.py — Generates a minimal but valid synthetic APK for testing.

Binary format derived directly from Androguard 4.x source:
  - ARSCHeader reads: struct.unpack('<HHL', buff.read(8))
    i.e. type(uint16) + header_size(uint16) + chunk_size(uint32)
  - XML event chunks must have header_size == 16 (0x10)
  - String pool type = 0x0001, header_size = 28
  - Resource map type = 0x0180

Run: python create_test_apk.py
Output: test_vulnerable_app.apk
"""
from __future__ import annotations

import io
import struct
import zipfile
import zlib
from pathlib import Path

# ---------------------------------------------------------------------------
# AXML chunk type constants (uint16 values)
# ---------------------------------------------------------------------------
RES_XML_TYPE                = 0x0003
RES_STRING_POOL_TYPE        = 0x0001
RES_XML_RESOURCE_MAP_TYPE   = 0x0180
RES_XML_START_NAMESPACE     = 0x0100
RES_XML_END_NAMESPACE       = 0x0101
RES_XML_START_ELEMENT       = 0x0102
RES_XML_END_ELEMENT         = 0x0103

# AXML attribute value types
TYPE_NULL    = 0x00
TYPE_REF     = 0x01
TYPE_STRING  = 0x03
TYPE_INT     = 0x10
TYPE_BOOL    = 0x12


def pack_header(chunk_type: int, header_size: int, chunk_size: int) -> bytes:
    """Pack an ARSCHeader: type(H=2B) header_size(H=2B) chunk_size(I=4B)."""
    return struct.pack('<HHI', chunk_type, header_size, chunk_size)


# ---------------------------------------------------------------------------
# String pool encoder (UTF-16-LE, flags=0)
# ---------------------------------------------------------------------------

def encode_string_pool(strings: list[str]) -> bytes:
    """Encode an AXML string pool chunk.

    Format: header(28B) + offsets(4B * n) + encoded_strings
    """
    # Encode each string: uint16 char-length + UTF-16-LE data + null terminator
    enc: list[bytes] = []
    for s in strings:
        raw = s.encode("utf-16-le")
        enc.append(struct.pack("<H", len(s)) + raw + b"\x00\x00")

    # Build offset table (offsets relative to start of string data, not header)
    offsets: list[int] = []
    off = 0
    for e in enc:
        offsets.append(off)
        off += len(e)

    HEADER_SIZE = 28
    offsets_data  = struct.pack(f"<{len(strings)}I", *offsets)
    strings_data  = b"".join(enc)

    # strings_start = distance from chunk start to first string byte
    strings_start = HEADER_SIZE + len(offsets_data)
    chunk_size    = strings_start + len(strings_data)

    header = struct.pack(
        "<IIIII",
        len(strings),   # string_count
        0,              # style_count
        0,              # flags  (0 = UTF-16)
        strings_start,  # stringsStart
        0,              # stylesStart
    )
    return (
        pack_header(RES_STRING_POOL_TYPE, HEADER_SIZE, chunk_size)
        + header
        + offsets_data
        + strings_data
    )


# ---------------------------------------------------------------------------
# Resource map chunk (maps attr name string indices → Android resource IDs)
# ---------------------------------------------------------------------------

def encode_resource_map(res_ids: list[int]) -> bytes:
    """Encode the XML resource map chunk."""
    chunk_size = 8 + 4 * len(res_ids)
    return pack_header(RES_XML_RESOURCE_MAP_TYPE, 8, chunk_size) + struct.pack(
        f"<{len(res_ids)}I", *res_ids
    )


# ---------------------------------------------------------------------------
# XML event chunk helpers
# ---------------------------------------------------------------------------

def _xml_event_header(chunk_type: int, body_size: int) -> bytes:
    """Encode a 16-byte XML event header (ARSCHeader(8) + line(4) + comment(4))."""
    chunk_size = 16 + body_size
    return (
        pack_header(chunk_type, 16, chunk_size)
        + struct.pack("<II", 1, 0xFFFFFFFF)   # line_number=1, comment=NONE
    )


def encode_start_namespace(prefix_idx: int, uri_idx: int) -> bytes:
    body = struct.pack("<II", prefix_idx, uri_idx)
    return _xml_event_header(RES_XML_START_NAMESPACE, len(body)) + body


def encode_end_namespace(prefix_idx: int, uri_idx: int) -> bytes:
    body = struct.pack("<II", prefix_idx, uri_idx)
    return _xml_event_header(RES_XML_END_NAMESPACE, len(body)) + body


def encode_end_element(ns_idx: int, name_idx: int) -> bytes:
    body = struct.pack("<II", ns_idx, name_idx)
    return _xml_event_header(RES_XML_END_ELEMENT, len(body)) + body


def encode_attr(ns_idx: int, name_idx: int, raw_idx: int,
                value_type: int, value_data: int) -> bytes:
    """Encode a single 20-byte attribute."""
    return struct.pack("<IIIHHI", ns_idx, name_idx, raw_idx,
                       0x1000 | (value_type & 0xFF),  # size(2)=16, res0(1)=0, dataType(1)
                       0,                              # padding to maintain packing
                       value_data)


def _attr_value(value_type: int, value_data: int) -> tuple[int, int]:
    """Return (value_size_and_type, value_data) packed fields."""
    return value_type, value_data


def encode_start_element(ns_idx: int, name_idx: int, attrs: list[bytes]) -> bytes:
    """Encode a start-element chunk with attribute list."""
    attr_count  = len(attrs)
    ATTR_SIZE   = 20
    # After event header (16B): ns(4) name(4) attrStart(2) attrSize(2) attrCount(2) idIdx(2) classIdx(2) styleIdx(2)
    ext_header  = struct.pack("<IIHHHHH",
                              ns_idx, name_idx,
                              0x0014,      # attributeStart = 20 (size of this ext header)
                              ATTR_SIZE,   # attributeSize
                              attr_count,
                              0, 0)        # idAttributeIndex, classAttributeIndex
    # styleAttributeIndex is missing — add it
    ext_header += struct.pack("<H", 0)

    body = ext_header + b"".join(attrs)
    return _xml_event_header(RES_XML_START_ELEMENT, len(body)) + body


def make_attr(ns_idx: int, name_idx: int, raw_idx: int,
              data_type: int, value: int) -> bytes:
    """Build a 20-byte attribute struct.

    Androguard reads the type field as: struct.unpack('<HBBi', ...)
      bytes 0-1: value_size (always 8)
      byte 2:    res0 (0)
      byte 3:    dataType

    As a little-endian uint32: value_size in low 2 bytes, dataType in high byte.
    """
    type_field = (data_type << 24) | 0x00000008
    return struct.pack("<IIIIi",
                       ns_idx,
                       name_idx,
                       raw_idx,
                       type_field,
                       value)


# ---------------------------------------------------------------------------
# Build the full binary AXML manifest
# ---------------------------------------------------------------------------

def build_axml_manifest() -> bytes:
    ANDROID_NS = "http://schemas.android.com/apk/res/android"
    PKG        = "com.test.vulnerableapp"

    # ---- String table (order matters — indices used throughout) ----
    strings = [
        ANDROID_NS,                                      # 0  ns uri
        "",                                              # 1  empty (ns prefix placeholder)
        # attribute names
        "package",                                       # 2
        "versionCode",                                   # 3
        "versionName",                                   # 4
        "minSdkVersion",                                 # 5
        "targetSdkVersion",                              # 6
        "name",                                          # 7
        "debuggable",                                    # 8
        "allowBackup",                                   # 9
        "usesCleartextTraffic",                          # 10
        "networkSecurityConfig",                         # 11
        "label",                                         # 12
        "exported",                                      # 13
        # element names
        "manifest",                                      # 14
        "uses-sdk",                                      # 15
        "uses-permission",                               # 16
        "application",                                   # 17
        "activity",                                      # 18
        "service",                                       # 19
        "receiver",                                      # 20
        "intent-filter",                                 # 21
        "action",                                        # 22
        "category",                                      # 23
        # value strings
        PKG,                                             # 24
        "1",                                             # 25
        "1.0",                                           # 26
        "android.permission.INTERNET",                   # 27
        "android.permission.CAMERA",                     # 28
        "android.permission.READ_SMS",                   # 29
        "android.permission.ACCESS_FINE_LOCATION",       # 30
        "android.permission.RECORD_AUDIO",               # 31
        "android.permission.READ_CONTACTS",              # 32
        "android.permission.WRITE_EXTERNAL_STORAGE",     # 33
        "VulnerableTestApp",                             # 34
        "@xml/network_security_config",                  # 35
        "com.test.vulnerableapp.MainActivity",           # 36
        "com.test.vulnerableapp.DataSyncService",        # 37
        "com.test.vulnerableapp.TokenReceiver",          # 38
        "android.intent.action.MAIN",                    # 39
        "android.intent.category.LAUNCHER",              # 40
        "com.test.vulnerableapp.RECEIVE_TOKEN",          # 41
    ]
    def si(s: str) -> int:
        return strings.index(s)

    NS   = si(ANDROID_NS)   # 0
    NONE = 0xFFFFFFFF
    EMPTY_IDX = 1

    # ---- Resource IDs for attribute names (same order as attr names above) ----
    # These are the android: attribute resource IDs from public.xml
    attr_name_indices = [2,3,4,5,6,7,8,9,10,11,12,13]  # string indices of attr names
    attr_res_ids = [
        0x0101021B,  # package (not a real attr but needed for manifest elem)
        0x0101021B,  # versionCode
        0x0101021C,  # versionName
        0x0101020C,  # minSdkVersion
        0x01010270,  # targetSdkVersion
        0x01010003,  # name
        0x0101000F,  # debuggable
        0x01010280,  # allowBackup
        0x010104EC,  # usesCleartextTraffic
        0x010104E1,  # networkSecurityConfig
        0x01010001,  # label
        0x01010010,  # exported
    ]

    def aattr(name_str: str, data_type: int, value: int, raw: int = NONE) -> bytes:
        """Shorthand: android-namespaced attribute."""
        return make_attr(NS, si(name_str), raw, data_type, value)

    # ---- Build chunk list ----
    chunks: list[bytes] = []

    # Namespace declaration
    chunks.append(encode_start_namespace(EMPTY_IDX, NS))

    # <manifest package="..." versionCode="1" versionName="1.0">
    chunks.append(encode_start_element(NONE, si("manifest"), [
        make_attr(NONE, si("package"), si(PKG), TYPE_STRING, si(PKG)),
        aattr("versionCode", TYPE_INT, 1),
        aattr("versionName", TYPE_STRING, si("1.0"), si("1.0")),
    ]))

    # <uses-sdk minSdk="16" targetSdk="25"/>
    chunks.append(encode_start_element(NONE, si("uses-sdk"), [
        aattr("minSdkVersion",    TYPE_INT, 16),
        aattr("targetSdkVersion", TYPE_INT, 25),
    ]))
    chunks.append(encode_end_element(NONE, si("uses-sdk")))

    # <uses-permission> x 7
    for perm_str in [
        "android.permission.INTERNET",
        "android.permission.CAMERA",
        "android.permission.READ_SMS",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.RECORD_AUDIO",
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_EXTERNAL_STORAGE",
    ]:
        chunks.append(encode_start_element(NONE, si("uses-permission"), [
            aattr("name", TYPE_STRING, si(perm_str), si(perm_str)),
        ]))
        chunks.append(encode_end_element(NONE, si("uses-permission")))

    # <application label="..." debuggable="true" allowBackup="true"
    #              usesCleartextTraffic="true" networkSecurityConfig="...">
    chunks.append(encode_start_element(NONE, si("application"), [
        aattr("label",                 TYPE_STRING, si("VulnerableTestApp"), si("VulnerableTestApp")),
        aattr("debuggable",            TYPE_BOOL,   NONE),
        aattr("allowBackup",           TYPE_BOOL,   NONE),
        aattr("usesCleartextTraffic",  TYPE_BOOL,   NONE),
        aattr("networkSecurityConfig", TYPE_STRING,
              si("@xml/network_security_config"), si("@xml/network_security_config")),
    ]))

    # <activity name="...MainActivity" exported="true">
    chunks.append(encode_start_element(NONE, si("activity"), [
        aattr("name",     TYPE_STRING, si("com.test.vulnerableapp.MainActivity"),
              si("com.test.vulnerableapp.MainActivity")),
        aattr("exported", TYPE_BOOL,   NONE),
    ]))
    chunks.append(encode_start_element(NONE, si("intent-filter"), []))
    chunks.append(encode_start_element(NONE, si("action"), [
        aattr("name", TYPE_STRING, si("android.intent.action.MAIN"),
              si("android.intent.action.MAIN")),
    ]))
    chunks.append(encode_end_element(NONE, si("action")))
    chunks.append(encode_start_element(NONE, si("category"), [
        aattr("name", TYPE_STRING, si("android.intent.category.LAUNCHER"),
              si("android.intent.category.LAUNCHER")),
    ]))
    chunks.append(encode_end_element(NONE, si("category")))
    chunks.append(encode_end_element(NONE, si("intent-filter")))
    chunks.append(encode_end_element(NONE, si("activity")))

    # <service name="...DataSyncService" exported="true"/>
    chunks.append(encode_start_element(NONE, si("service"), [
        aattr("name",     TYPE_STRING, si("com.test.vulnerableapp.DataSyncService"),
              si("com.test.vulnerableapp.DataSyncService")),
        aattr("exported", TYPE_BOOL,   NONE),
    ]))
    chunks.append(encode_end_element(NONE, si("service")))

    # <receiver name="...TokenReceiver" exported="true">
    chunks.append(encode_start_element(NONE, si("receiver"), [
        aattr("name",     TYPE_STRING, si("com.test.vulnerableapp.TokenReceiver"),
              si("com.test.vulnerableapp.TokenReceiver")),
        aattr("exported", TYPE_BOOL,   NONE),
    ]))
    chunks.append(encode_start_element(NONE, si("intent-filter"), []))
    chunks.append(encode_start_element(NONE, si("action"), [
        aattr("name", TYPE_STRING, si("com.test.vulnerableapp.RECEIVE_TOKEN"),
              si("com.test.vulnerableapp.RECEIVE_TOKEN")),
    ]))
    chunks.append(encode_end_element(NONE, si("action")))
    chunks.append(encode_end_element(NONE, si("intent-filter")))
    chunks.append(encode_end_element(NONE, si("receiver")))

    chunks.append(encode_end_element(NONE, si("application")))
    chunks.append(encode_end_element(NONE, si("manifest")))
    chunks.append(encode_end_namespace(EMPTY_IDX, NS))

    # ---- Assemble ----
    string_pool  = encode_string_pool(strings)
    resource_map = encode_resource_map(attr_res_ids)
    inner        = string_pool + resource_map + b"".join(chunks)
    file_size    = 8 + len(inner)
    outer_header = pack_header(RES_XML_TYPE, 8, file_size)
    return outer_header + inner


# ---------------------------------------------------------------------------
# DEX builder with correct Adler32 checksum
# ---------------------------------------------------------------------------

def encode_uleb128(value: int) -> bytes:
    result = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            byte |= 0x80
        result.append(byte)
        if not value:
            break
    return bytes(result)


def build_dex_with_strings(strings: list[str]) -> bytes:
    """Build a minimal valid DEX file containing the given string constants."""
    # Encode strings: ULEB128 length + UTF-8 bytes + null terminator
    string_parts: list[bytes] = []
    for s in strings:
        raw = s.encode("utf-8")
        string_parts.append(encode_uleb128(len(s)) + raw + b"\x00")

    HEADER_SIZE      = 112
    n_strings        = len(strings)
    STRING_IDS_SIZE  = 4 * n_strings
    string_ids_off   = HEADER_SIZE
    str_data_off     = string_ids_off + STRING_IDS_SIZE

    # String ID table and string data
    string_ids = bytearray()
    string_data = bytearray()
    cur = str_data_off
    for part in string_parts:
        string_ids += struct.pack("<I", cur)
        string_data += part
        cur += len(part)

    # Pad to 4-byte alignment
    while len(string_data) % 4:
        string_data += b"\x00"

    data_size = STRING_IDS_SIZE + len(string_data)
    file_size = HEADER_SIZE + data_size

    # Build post-checksum body (everything from byte 12 onward)
    body = struct.pack(
        "<20s" + "I" * 20,
        b"\x00" * 20,    # SHA-1 (not validated by Androguard string scan)
        file_size,
        HEADER_SIZE,
        0x12345678,      # endian tag
        0, 0,            # link_size, link_off
        0,               # map_off
        n_strings,       # string_ids_size
        string_ids_off,  # string_ids_off
        0, 0,            # type_ids_size, type_ids_off
        0, 0,            # proto_ids_size, proto_ids_off
        0, 0,            # field_ids_size, field_ids_off
        0, 0,            # method_ids_size, method_ids_off
        0, 0,            # class_defs_size, class_defs_off
        data_size,       # data_size
        string_ids_off,  # data_off
    ) + bytes(string_ids) + bytes(string_data)

    adler = zlib.adler32(body) & 0xFFFFFFFF
    return b"dex\n035\x00" + struct.pack("<I", adler) + body


# ---------------------------------------------------------------------------
# Secrets to embed in the DEX string pool
# ---------------------------------------------------------------------------

DEX_STRINGS = sorted([
    "AIzaSyD-FAKE_GOOGLE_API_KEY_FOR_TESTING_XYZ",
    "AKIAFAKEAWSACCESSKEYID",
    "api_key=sk-live_super_secret_token_abc123xyz",
    "password=admin123secure",
    "secret=MySuperSecretPassword2024!",
    "Authorization: Basic dXNlcjpwYXNzd29yZA==",
    "http://192.168.1.100:8080/api/v1/users",
    "MD5", "DES", "AES/ECB/PKCS5Padding", "SHA-1", "RC4",
    "com.test.vulnerableapp.MainActivity",
    "android.intent.action.MAIN",
    "VulnerableTestApp",
    "Ljava/security/MessageDigest;",
    "Ljavax/crypto/Cipher;",
    "getInstance",
])

NSC_XML = """\
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system"/>
            <certificates src="user"/>
        </trust-anchors>
    </base-config>
    <domain-config cleartextTrafficPermitted="true">
        <domain includeSubdomains="true">api.example.com</domain>
    </domain-config>
</network-security-config>
"""


# ---------------------------------------------------------------------------
# Assemble APK
# ---------------------------------------------------------------------------

def create_test_apk(output: str = "test_vulnerable_app.apk") -> None:
    print(f"Building synthetic test APK: {output}")

    manifest = build_axml_manifest()
    print(f"  Binary AXML: {len(manifest)} bytes")

    dex = build_dex_with_strings(DEX_STRINGS)
    print(f"  DEX:         {len(dex)} bytes  ({len(DEX_STRINGS)} strings)")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", manifest)
        zf.writestr("classes.dex", dex)
        zf.writestr("res/xml/network_security_config.xml", NSC_XML.encode())
        zf.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\r\n\r\n")

    Path(output).write_bytes(buf.getvalue())
    kb = len(buf.getvalue()) / 1024
    print(f"  APK:         {output} ({kb:.1f} KB)\n")
    print("  Embedded vulnerabilities:")
    print("    7 dangerous permissions (INTERNET, CAMERA, READ_SMS, …)")
    print("    1 exported Activity  — no permission guard")
    print("    1 exported Service   — no permission guard")
    print("    1 exported Receiver  — no permission guard")
    print("    android:usesCleartextTraffic=true")
    print("    targetSdkVersion=25 (below 28)")
    print("    NSC: global cleartext + user cert trust")
    print("    Hardcoded secrets in DEX string pool")
    print("    Weak crypto strings: MD5, DES, AES/ECB, RC4, SHA-1")
    print(f"\n  Run: python triage.py --apk {output} --skip-ai")


if __name__ == "__main__":
    create_test_apk()
