# page: Python Bindings for the age encryption tool

age is a simple, secure and modern encryption tool with small explicit keys, no
config options, and UNIX-style composability. The format specification is at
[age-encryption.org/v1](https://age-encryption.org/v1).

page is a Python library using the Rust implementation of the age tool. It is pronounced like the Japanese
[パゲ](https://translate.google.com/#view=home&op=translate&sl=ja&tl=en&text=%E3%83%91%E3%82%B2)
(with a hard g).

To discuss the spec or other age related topics, please email
[the mailing list](https://groups.google.com/d/forum/age-dev) at
age-dev@googlegroups.com. age was designed by
[@Benjojo12](https://twitter.com/Benjojo12) and
[@FiloSottile](https://twitter.com/FiloSottile).

The reference interoperable Golang implementation is available at
[filippo.io/age](https://filippo.io/age).
The Rust implementation is available at
[https://github.com/str4d/rage](https://github.com/str4d/rage)

## Usage

You can use page's encryption functions in two ways,
either using identity-based encryption:
```python
from page import encrypt, decrypt, Identity, Recipient

rc = Recipient("age1ppvqwzgdynzjmy04drg9h55xv0clhr4frtgnvy4uwkvk4jf4gu0sf63nar")
id = Identity("""
AGE-SECRET-KEY-1CZP3Q5EC25V8SK003Y8FYQNH7JPCCVMCRMZYSRX7E2JV3U0C09PSS5MEGZ
""")

encrypted_msg = encrypt(b"My Important Message", public_keys=[rc])
msg = decrypt(encrypted_msg, private_keys=[id])
assert msg == b"My Important Message"
```
or, using simple passphrase-based encryption:
```python
from page import encrypt, decrypt

encrypted_msg = encrypt(b"My Important Message", passphrase="My secret password")
msg = decrypt(encrypted_msg, passphrase="My secret password")
assert msg == b"My Important Message"
```

### Multiple recipients

Files can be encrypted to multiple recipients.
Every recipient will be able to decrypt the file.

```python
from page import encrypt, decrypt, Identity, Recipient

rc1 = Recipient("...")
rc2 = Recipient("...")
id1 = Identity("...")
id2 = Identity("...")

encrypted_msg = encrypt(b"My Important Message", public_keys=[rc1, rc2])
msg1 = decrypt(encrypted_msg, private_keys=[id1])
msg2 = decrypt(encrypted_msg, private_keys=[id2])
assert msg1 == msg2
```

### Passphrases

Page can be used to generate a secure passphrase.

```bash
from page import generate_passphrase

# Creates 10 words randomly chosen from BIP39 wordlist
print(f"Secure passphrase: {generate_passphrase()}")
# Secure passphrase: kiwi-general-undo-bubble-dwarf-dizzy-fame-side-sunset-sibling
```

### SSH keys

page also supports encrypting to `ssh-rsa` and `ssh-ed25519` SSH public keys,
and decrypting with the respective private key.

```
from page import encrypt, decrypt, Identity, Recipient

rc = Recipient.from_file("~/.ssh/id_ed25519.pub")
id = Identity.from_file("~/.ssh/id_ed25519")

encrypted_msg = encrypt(b"My Important Message", public_keys=[rc])
msg = decrypt(encrypted_msg, private_keys=[id])
assert msg == b"My Important Message"
```

`ssh-rsa` support is currently behind the `unstable` feature flag.

Note that SSH key support employs more complex cryptography, and embeds a public
key tag in the encrypted message, making it possible to track files that are
encrypted to a specific public key.

## Installation

You can install page using pip:
```bash
$ pip install page
```

Help from new packagers is very welcome.

## License

Licensed under Apache License, Version 2.0 ([LICENSE](LICENSE))

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, shall be as defined in the
Apache-2.0 license, without any additional terms or conditions.
