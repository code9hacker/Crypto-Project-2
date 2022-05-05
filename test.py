from crypto_library import get_password_hash_old, rtp_protect

print(rtp_protect(b'\x80\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' + (b'\xd4' * 160)))