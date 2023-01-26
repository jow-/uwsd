#!/bin/sh

printf "Content-Type: text/plain\r\n\r\n"

echo "My file descriptors:"
ls -lh /proc/self/fd
echo ""

echo "My environment variables:"
env | sort
echo ""

echo "My HTTP request data (base64 encoded):"
t=$(mktemp)
cat > "$t"
base64 < "$t"
rm "$t"
echo ""
