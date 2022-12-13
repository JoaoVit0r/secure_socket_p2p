
def cast_to_bytes(to_bytes: str | bytes, format='utf-8') -> bytes:
    if isinstance(to_bytes, str):
        return to_bytes.encode(format)
    return to_bytes

def cast_to_str(to_str: str | bytes, format='utf-8') -> str:
    if isinstance(to_str, bytes):
        return to_str.decode(format)
    return to_str
