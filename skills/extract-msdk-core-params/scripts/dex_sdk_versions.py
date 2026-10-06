"""Read SDK version constants from DEX metadata without executing bytecode."""

import struct
import sys


TARGETS = {
    "Lcom/tencent/connect/common/Constants;": ("SDK_VERSION", "qq_sdk_version"),
    "Lcom/itop/gcloud/msdk/pixui/core/BuildConfig;": ("VERSION_NAME", "msdk_version"),
}
MAX_STRING_CACHE_BYTES = 8 * 1024 * 1024
MAX_STRING_CACHE_ENTRIES = 65536


class DexError(ValueError):
    pass


def sdk_versions(data):
    def unpack(fmt, offset):
        if offset < 0 or offset + struct.calcsize(fmt) > len(data):
            raise DexError("invalid_dex_bounds")
        return struct.unpack_from(fmt, data, offset)

    def uleb(offset):
        result = 0
        for shift in range(0, 35, 7):
            value, = unpack("<B", offset)
            offset += 1
            result |= (value & 127) << shift
            if not value & 128:
                return result, offset
        raise DexError("invalid_dex_uleb")

    def table(header, item_size):
        count, offset = unpack("<II", header)
        if count > 1_000_000 or offset + count * item_size > len(data):
            raise DexError("invalid_dex_table")
        return count, offset

    if len(data) < 112 or data[:4] != b"dex\n" or data[7] != 0:
        raise DexError("unsupported_dex")
    size, header_size, endian = unpack("<III", 32)
    if size != len(data) or header_size != 112 or endian != 0x12345678:
        raise DexError("unsupported_dex_layout")
    string_count, string_table = table(56, 4)
    type_count, type_table = table(64, 4)
    field_count, field_table = table(80, 8)
    class_count, class_table = table(96, 32)
    cache = {}
    cache_bytes = 0

    def string(index):
        nonlocal cache_bytes
        if index >= string_count:
            raise DexError("invalid_dex_string")
        string_offset, = unpack("<I", string_table + index * 4)
        # Several string IDs can share one data offset. Keying by ID would
        # decode and retain the same long string once for every alias.
        if string_offset not in cache:
            if len(cache) >= MAX_STRING_CACHE_ENTRIES:
                raise DexError("dex_string_cache_limit_exceeded")
            _, offset = uleb(string_offset)
            end = data.find(b"\0", offset, offset + 65536)
            if end < 0:
                raise DexError("invalid_dex_string")
            # Target class, field and version strings are ASCII. Other strings
            # may use modified UTF-8 and are not interpreted as configuration.
            value = data[offset:end].decode("utf-8", errors="replace")
            cache_bytes += sys.getsizeof(value)
            # Different offsets can still overlap almost the same bytes.
            # Bound decoded storage as well as deduplicating identical offsets.
            if cache_bytes > MAX_STRING_CACHE_BYTES:
                raise DexError("dex_string_cache_limit_exceeded")
            cache[string_offset] = value
        return cache[string_offset]

    def type_name(index):
        if index >= type_count:
            raise DexError("invalid_dex_type")
        return string(unpack("<I", type_table + index * 4)[0])

    def encoded(offset, depth=0):
        if depth > 32:
            raise DexError("dex_value_depth_exceeded")
        tag, = unpack("<B", offset)
        offset += 1
        kind, width = tag & 31, (tag >> 5) + 1
        if kind in (0x1E, 0x1F):
            return None, offset
        if kind in (0x1C, 0x1D):
            if width != 1:
                raise DexError("invalid_dex_value")
            if kind == 0x1D:
                _, offset = uleb(offset)
            count, offset = uleb(offset)
            if count > 65536:
                raise DexError("dex_value_limit_exceeded")
            for _ in range(count):
                if kind == 0x1D:
                    _, offset = uleb(offset)
                _, offset = encoded(offset, depth + 1)
            return None, offset
        if kind not in (0, 2, 3, 4, 6, 0x10, 0x11, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B):
            raise DexError("unsupported_dex_value")
        raw = bytes(unpack(f"<{width}B", offset))
        value = int.from_bytes(raw, "little")
        return (string(value) if kind == 0x17 else None), offset + width

    found = []
    for index in range(class_count):
        record = unpack("<8I", class_table + index * 32)
        name = type_name(record[0])
        if name not in TARGETS or not record[6] or not record[7]:
            continue
        wanted, field = TARGETS[name]
        count, offset = uleb(record[6])
        if count > field_count:
            raise DexError("invalid_static_fields")
        for _ in range(3):
            _, offset = uleb(offset)
        fields, field_index = [], 0
        for _ in range(count):
            delta, offset = uleb(offset)
            _, offset = uleb(offset)
            field_index += delta
            if field_index >= field_count:
                raise DexError("invalid_dex_field")
            owner, _, string_index = unpack("<HHI", field_table + field_index * 8)
            if owner != record[0]:
                raise DexError("invalid_dex_field_owner")
            fields.append(string(string_index))
        count, offset = uleb(record[7])
        if count > len(fields):
            raise DexError("invalid_static_values")
        for index in range(count):
            location = offset
            value, offset = encoded(offset)
            if fields[index] == wanted and isinstance(value, str):
                found.append((field, value, f"{name}->{wanted}@0x{location:x}"))
    return found
