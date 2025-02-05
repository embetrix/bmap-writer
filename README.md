
# bmap-writer

[![CI](https://github.com/embetrix/bmap-writer/actions/workflows/integration.yml/badge.svg)](https://github.com/embetrix/bmap-writer/actions/workflows/integration.yml)

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

## Requirements

- C++ compiler
- CMake
- Libarchive
- TinyXML-2

## Build and Installation

### Install Dependencies

#### Ubuntu

```sh
sudo apt-get update
sudo apt-get install -y libarchive-dev libtinyxml2-dev
```

## Build

```sh
cmake .
make
```

## Test

```sh
ctest -V
```

## Install

```sh
sudo make install
```

## Usage

```sh
bmap-writer [-hvn] <image-file> [<bmap-file>] <target-device>
```

* `-n` : Skip checksum verification
* `-v` : Show version
* `-h` : Show this help and exit
* `<bmap-file>`: Optional. If not provided, it will be searched in the same path as the input `<image-file>`.

To use stdin as source of the image file, `<image-file>` shall be equal to `-` and `<bmap-file>` shall be present.

### Streaming mode

Streaming mode, i.e. writing data while it's being received, is supported through piping from external applications.
The BMAP file shall be present and available before the data streaming is started.

Some examples are presented below:

* Download from an HTTP server using `wget`:
```bash
wget -O - http://myserver.com/image.bmap > image.bmap
wget -O - http://myserver.com/image.gz | bmap-writer - image.bmap /dev/sdX
```
* Download from a FTP server using `wget`:
```bash
wget -O - ftp://user@myserver.com:2121/image.bmap > image.bmap
wget -O - ftp://user@myserver.com:2121/image.gz | bmap-writer - image.bmap /dev/sdX
```
* Download from a SFTP host using `curl`:
```bash
curl -u user:password sftp://hostname/path/to/image.bmap > image.bmap
curl -u user:password sftp://hostname/path/to/image.gz | bmap-writer - image.bmap /dev/sdX
```

Note: the [bmap-writer-stream.sh](bmap-writer-stream.sh) script can be used for stream processing tasks.
 
## Yocto/Buildroot Integration

`bmap-writer` is already available in [meta-openembedded](https://github.com/openembedded/meta-openembedded/blob/master/meta-oe/recipes-support/bmap-writer) and [buildroot](https://github.com/buildroot/buildroot/tree/master/package/bmap-writer
)


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

