import pytest
from page import Identity, encrypt, PageUsageError

MESSAGE = "This is my super secret message!"
PASSPHRASE = "This is my super secret passphrase!"

SSH_ED25519_SK = """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACB7Ci6nqZYaVvrjm8+XbzII89TsXzP111AflR7WeorBjQAAAJCfEwtqnxML
agAAAAtzc2gtZWQyNTUxOQAAACB7Ci6nqZYaVvrjm8+XbzII89TsXzP111AflR7WeorBjQ
AAAEADBJvjZT8X6JRJI8xVq/1aU8nMVgOtVnmdwqWwrSlXG3sKLqeplhpW+uObz5dvMgjz
1OxfM/XXUB+VHtZ6isGNAAAADHN0cjRkQGNhcmJvbgE=
-----END OPENSSH PRIVATE KEY-----"""
SSH_ED25519_PK = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHsKLqeplhpW+uObz5dvMgjz1OxfM/XXUB+VHtZ6isGN alice@rust"

AGE_SK = "AGE-SECRET-KEY-1GQ9778VQXMMJVE8SK7J6VT8UJ4HDQAJUVSFCWCM02D8GEWQ72PVQ2Y5J33"
AGE_PK = "age1t7rxyev2z3rw82stdlrrepyc39nvn86l5078zqkf5uasdy86jp6svpy7pa"


@pytest.mark.parametrize('raw_skey,pkey', [
    (SSH_ED25519_SK, SSH_ED25519_PK),
    (AGE_SK, AGE_PK),
])
def test_symmetric_encryption(raw_skey, pkey):
    skey = Identity.from_secret(raw_skey)

    enc_msg = encrypt(MESSAGE.encode('utf-8'), public_keys=[pkey])
    assert enc_msg != MESSAGE
    rec_msg = skey.decrypt(enc_msg)
    assert str(rec_msg, 'utf-8') == MESSAGE


def test_asymmetric_encryption_w_passphrase():
    skey1 = Identity.generate()
    skey2 = Identity.generate()

    enc_msg = encrypt(MESSAGE.encode('utf-8'), passphrase=PASSPHRASE)
    assert enc_msg != MESSAGE
    rec_msg = skey2.decrypt(enc_msg, passphrase=PASSPHRASE)
    assert str(rec_msg, 'utf-8') == MESSAGE


def test_errors():
    # Secret key format is invalid
    with pytest.raises(PageUsageError):
        Identity.from_secret("Bad Key")

    skey = Identity.from_secret(AGE_SK)
    # Must specify either passphrase or publickey
    with pytest.raises(PageUsageError):
        encrypt(MESSAGE.encode('utf-8'))


def test_mixed_keys():
    skey1 = Identity.from_secret(SSH_ED25519_SK)
    skey2 = Identity.from_secret(AGE_SK)

    enc_msg = encrypt(MESSAGE.encode('utf-8'), public_keys=[AGE_PK])
    assert enc_msg != MESSAGE
    rec_msg = skey2.decrypt(enc_msg)
    assert str(rec_msg, 'utf-8') == MESSAGE
