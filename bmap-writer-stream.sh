#!/bin/sh -e

export PATH=$PWD:$PATH

IMAGE_URL=$(echo "$1" | grep -P '^(https?|s?ftp)://([\w\-]+(:[\w\-]+)?@)?([\da-zA-Z\.-]+)(:\d+)?(/[^\s]*)?$' > /dev/null && echo "$1" || echo "")
DEVICE=$2

WGET=$(which wget)
BMAP_WRITER=$(which bmap-writer)

if [ -z "$IMAGE_URL" ]; then
    echo "Usage: $0 <url> <device>"
    exit 1
fi

if [ -z "$WGET" ] && [ -z "$BMAP_WRITER" ]; then
    echo "Please install wget/bmap-writer"
    exit 1
fi

BMAP_URL=$(echo "$IMAGE_URL" | sed 's/\.[^.]*$/.bmap/')
BMAP_FILE=$(echo "$BMAP_URL" | sed 's/.*\///')

BMAP_FILE="${BMAP_FILE}_"
echo "Downloading $BMAP_URL to $BMAP_FILE"
$WGET -q $BMAP_URL -O $BMAP_FILE
echo "Streaming $IMAGE_URL to $DEVICE"
$WGET -q $IMAGE_URL -O - | $BMAP_WRITER - $BMAP_FILE $DEVICE

