#!/bin/bash -e

# This script tests the bmap-writer tool

if [ ! -f test.img ]; then
    echo "## Create a file with random data"
    dd if=/dev/urandom of=test.img bs=1M count=10 > /dev/null 2>&1
    dd if=/dev/urandom of=test.img bs=1M count=2 seek=12 conv=notrunc  > /dev/null 2>&1
    dd if=/dev/urandom of=test.img bs=1M count=5 seek=16 conv=notrunc  > /dev/null 2>&1
    dd if=/dev/urandom of=test.img bs=4k count=1 seek=131072 conv=notrunc  > /dev/null 2>&1
fi

if [ ! -f test.img.tar ]; then
    echo "## Enclose the file inside tar"
    tar -cf test.img.tar test.img
fi

if [ ! -f test.img.tar.gz ]; then
    echo "## Enclose the file inside tar.gz"
    tar -czf test.img.tar.gz test.img
fi

if [ ! -f test.img.bz2 ]; then
    echo "## Compress the file with bzip2"
    bzip2 -f -k -c test.img > test.img.bz2
fi

if [ ! -f test.img.gz ]; then
    echo "## Compress the file with gzip"
    gzip -9 test.img -c   > test.img.gz
fi

if [ ! -f test.img.lz4 ]; then
    echo "## Compress the file with lz4"
    lz4 -f -k -c test.img > test.img.lz4
fi

if [ ! -f test.img.lzo ]; then
    echo "## Compress the file with lzo"
    lzop -f -k -c test.img > test.img.lzo
fi

if [ ! -f test.img.xz ]; then
    echo "## Compress the file with xz"
    xz   -z test.img -c   > test.img.xz
fi

if [ ! -f test.img.zst ]; then
    echo "## Compress the file with zstd"
    zstd -f -k -c test.img > test.img.zst
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

echo "## Write the file with bmap-writer (with random write buffer size)"
./bmap-writer -b $(( $RANDOM * 1024 )) test.img test.img.bmap test.none.img.out
cmp test.img.out test.none.img.out

echo "## Write the file with bmap-writer and verify written data"
./bmap-writer -w test.img test.img.bmap test.none.img.out
cmp test.img.out test.none.img.out

echo "## Write the file with bmap-writer and skip checksum"
./bmap-writer -n test.img test.img.bmap test.none.img.out
cmp test.img.out test.none.img.out

echo "## Write the file with bmap-writer and tar"
./bmap-writer test.img.tar test.img.bmap test.tar.img.out
cmp test.img.out test.tar.img.out

echo "## Write the file with bmap-writer and tar+gzip"
./bmap-writer test.img.tar.gz test.img.bmap test.tar.gz.img.out
cmp test.img.out test.tar.gz.img.out

echo "## Write the file with bmap-writer and bzip2"
./bmap-writer test.img.bz2 test.img.bmap test.bz2.img.out
cmp test.img.out test.bz2.img.out

echo "## Write the file with bmap-writer and gzip"
./bmap-writer test.img.gz test.img.bmap test.gz.img.out
cmp test.img.out test.gz.img.out

echo "## Write the file with bmap-writer and lz4"
./bmap-writer test.img.lz4 test.img.bmap test.lz4.img.out
cmp test.img.out test.lz4.img.out

echo "## Write the file with bmap-writer and lzo"
./bmap-writer test.img.lzo test.img.bmap test.lzo.img.out
cmp test.img.out test.lzo.img.out

echo "## Write the file with bmap-writer and xz"
./bmap-writer test.img.xz test.img.bmap test.xz.img.out
cmp test.img.out test.xz.img.out

echo "## Write the file with bmap-writer and zstd"
./bmap-writer test.img.zst test.img.bmap test.zst.img.out
cmp test.img.out test.zst.img.out
