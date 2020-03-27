U2F Emulated
============

Software that emulate U2F through a virtual USB device using UHID
system API on linux.

# Usage

Run the program in privileged mode:
```shell
sudo ./u2F-emulated
```

Then visit any website that uses U2F, such as:
- https://webauthn.io/

# Building

Build the binary:
```shell
make
./setup
```

Test the project:
```shell
make check
```

Generate doc:
```
make doc
```

# License

This project is licensed under GPL-2.0

# Author

César `MattGorko` Belley <cesar.belley@lse.epita.fr>
