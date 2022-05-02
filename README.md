# pyrageencrypt: Python Bindings for the age encryption tool

AGE (actually good encryption) is a simple, secure and modern encryption tool
with small explicit keys, no config options, and UNIX-style composability.
The format specification is at
[age-encryption.org/v1](https://age-encryption.org/v1).

pyrageencrypt is a Python library using the Rust implementation of the age tool.
It is pronounced with a hard "g" like the Japanese
[パゲ](https://translate.google.com/#view=home&op=translate&sl=ja&tl=en&text=%E3%83%91%E3%82%B2)

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

You can use Python AGE encryption functions provided by the package in two ways,
either using identity-based encryption:
```python
from pyrageencrypt import encrypt, decrypt, Identity

rc = "age1ppvqwzgdynzjmy04drg9h55xv0clhr4frtgnvy4uwkvk4jf4gu0sf63nar"
id = Identity("""
AGE-SECRET-KEY-1CZP3Q5EC25V8SK003Y8FYQNH7JPCCVMCRMZYSRX7E2JV3U0C09PSS5MEGZ
""")

encrypted_msg = encrypt(b"My Important Message", public_keys=[rc])
msg = decrypt(encrypted_msg, private_keys=[id])
assert msg == b"My Important Message"
```
or, using simple passphrase-based encryption:
```python
from pyrageencrypt import encrypt, decrypt

encrypted_msg = encrypt(b"My Important Message", passphrase="My secret password")
msg = decrypt(encrypted_msg, passphrase="My secret password")
assert msg == b"My Important Message"
```

### Multiple recipients

Files can be encrypted to multiple recipients.
Every recipient will be able to decrypt the file.

```python
from pyrageencrypt import encrypt, decrypt, Identity

id1 = Identity.generate()
id2 = Identity.generate()

encrypted_msg = encrypt(b"My Important Message", public_keys=[*id1.public(), *id2.public()])
msg1 = decrypt(encrypted_msg, private_keys=[id1])
msg2 = decrypt(encrypted_msg, private_keys=[id2])
assert msg1 == msg2
```

## Installation

You can install the package using pip:
```bash
$ pip install pyrageencrypt
```

## License

Licensed under Apache License, Version 2.0 ([LICENSE](LICENSE))

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, shall be as defined in the
Apache-2.0 license, without any additional terms or conditions.
