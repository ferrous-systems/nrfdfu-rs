# nRF DFU Flashing Tool

[![crates.io](https://img.shields.io/crates/v/nrfdfu.svg)](https://crates.io/crates/nrfdfu)
[![docs.rs](https://docs.rs/nrfdfu/badge.svg)](https://docs.rs/nrfdfu/)

`nrfdfu-rs` is an implementation of the protocol used by the bootloader on the nRF family of microcontrollers.
It can be used to flash an ELF firmware file onto devices such as the [nRF52840 Dongle].

This tool was written to replace [`pc-nrfutil`] in our trainings, so it implements a subset of the features found there.

[nRF52840 Dongle]: https://www.nordicsemi.com/Software-and-tools/Development-Kits/nRF52840-Dongle
[`pc-nrfutil`]: https://github.com/NordicSemiconductor/pc-nrfutil

## Usage

Run the following command to install the `nrfdfu` executable on your system:

```shell
$ cargo install nrfdfu
```

The tool is designed to be passed an ELF file as follows:

```
$ nrfdfu path/to/firmware.elf
```

This allows using it as a Cargo runner to automatically flash your Rust firmware during `cargo run`.
Place the following in `.cargo/config.toml` to use `nrfdfu` as the Cargo runner:

```toml
[target.'cfg(all(target_arch = "arm", target_os = "none"))']
runner = "nrfdfu"
```
