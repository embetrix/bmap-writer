#!/bin/bash -e

# This script tests the bmap-writer tool

if [ ! -f test.img ]; then
    echo "## Create a file with random data"
    dd if=/dev/urandom of=test.img bs=1M count=10 > /dev/null 2>&1
    dd if=/dev/urandom of=test.img bs=1M count=2 seek=12 conv=notrunc  > /dev/null 2>&1
    dd if=/dev/urandom of=test.img bs=1M count=5 seek=16 conv=notrunc  > /dev/null 2>&1
fi

if [ ! -f test.img.gz ] || [ ! -f test.img.xz ]; then
    echo "## Compress the file with xz and gzip"
    xz   -z test.img -c   > test.img.xz
    gzip -9 test.img -c   > test.img.gz
fi

if [ ! -f test.img.bmap ] ; then
    echo "## Create a bmap file"
    bmaptool create test.img -o test.img.bmap
fi

echo "## Write the file with bmaptool as reference"
bmaptool copy test.img test.img.out

echo "## Write the file with bmap-writer"
./bmap-writer test.img test.img.bmap test.none.img.out
cmp test.img.out test.none.img.out

echo "## Write the file with bmap-writer and gzip"
./bmap-writer test.img.gz test.img.bmap test.gz.img.out
cmp test.img.out test.gz.img.out

echo "## Write the file with bmap-writer and xz"
./bmap-writer test.img.xz test.img.bmap test.xz.img.out
cmp test.img.out test.xz.img.out

echo "## Verify the xz decompression test passes"
if cmp -s test.img.out test.xz.img.out; then
    echo "xz decompression test passed"
else
    echo "xz decompression test failed"
    exit 1
fi
