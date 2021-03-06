# fusee-gelee
*Rust implementation of the [Fusée Gelée](https://github.com/Qyriad/fusee-launcher) exploit (CVE-2018-6242) for Tegra processors.*

Currently supported platforms:
- Linux via `libusb`.

## Instructions
1. Obtain executable version of the exploit launcher.
2. Obtain a payload suitable for use on the target device.
3. Execute the launcher, providing a path to the payload:
```sh
./fusee-gelee /path/to/fusee-primary.bin
```

## Building from source
Create a debug build:
```sh
git clone https://github.com/austinhartzheim/fusee-gelee.git
cd fusee-gelee
cargo build  # binary output to target/debug/fusee-gelee
```

Create a release build:
```sh
cargo build --release
```

## Developing
Unit tests are available to compare the payload generation output against a sample payload generated by the Python implementation. To run the tests:
```sh
cargo test
```

## License
Licensed under the terms of GPL version 2. See `LICENSE.txt` for details.