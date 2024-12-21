
# bmap-writer

![pipeline status](https://github.com/embetrix/bmap-writer/actions/workflows/cmake-single-platform.yml/badge.svg)

`bmap-writer` is a command-line utility designed to efficiently write disk images to storage devices using block mapping (BMAP). 
It serves as a lightweight alternative to the Yocto BMAP tool, specifically for embedded systems. 
Unlike the Yocto BMAP tool, `bmap-writer` is C++ based does not require Python and focuses solely on writing an image.

<p align ="center"><img src=bmap-writer.jpeg width=200 height=200 /></p>

## Key Features

- Provides a lightweight alternative specifically for embedded systems.
- Does not require Python, making it easier to integrate into various environments.
- Handles all compression filters that are supported by `libarchive`, decompressing the data on-the-fly during the writing process.
- Ensures data integrity by verifying checksums for each block.
- Writes only the necessary blocks, reducing the overall write time and wear on storage devices.

## How It Works

1. Create a BMAP file for your disk image using `bmaptool`.
2. Use `bmap-writer` to write the image to your target device, specifying the BMAP file for efficient block mapping.

## Usage

```
bmap-writer [-b <max-buf-size>] [-v] <image-file> <bmap-file> <target-device>
```

The `<max-buf-size>` parameter can be used to limit the write buffer size on systems with limited RAM.
It can be specified as a plain number or using the `K` (KiB), `M` (MiB), `G` (GiB) or `T` (TiB) suffixes.
If not specified, the write buffer size will be variable and will depend on the size of the ranges specified inside the BAMP file.

If `-n` is specified, the checksum verification is skipped.
If `-w` is specified, the written data is read back and verified against the checksum contained inside the BMAP file.
Otherwise, the checksum verification is performed on the data read from the image file.

## License

This project is licensed under the terms of the **GNU General Public License v3 (GPLv3)**.
You are free to use, modify, and distribute this software under the conditions outlined in the GPLv3 license.

For more information about the GPLv3 license, refer to the [LICENSE](LICENSE) file in this repository or visit [GNU's official page](https://www.gnu.org/licenses/gpl-3.0.html).


## Commercial License

For organizations or individuals requiring the use of `bmap-writer` in proprietary applications or with different licensing terms, a **commercial license** is available.

The commercial license provides:
- Freedom from the obligations imposed by the GPLv3 license.
- Priority access to updates, integration help, and extended documentation.
- Tailored development and deployment solutions.

To obtain a commercial license or inquire further, please contact: [**info@embetrix.com**](mailto:info@embetrix.com)


## Contributor License Agreement (CLA)

By submitting a pull request to this repository, you agree to the following terms:

1. You certify that your contribution is your original work or that you have the necessary rights to submit it.
2. You grant the project maintainers a perpetual, worldwide, non-exclusive, royalty-free, irrevocable license to:
   - Use, modify, sublicense, and distribute your contribution under the terms of the **GPLv3**.
   - Use, modify, sublicense, and distribute your contribution under alternative licenses, including commercial licenses.
3. You understand that you retain the copyright to your contribution but agree it may be relicensed under these terms.

