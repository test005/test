#!/bin/sh
# $Id: Build.sh,v 1.1 2004/08/25 20:22:58 s-nomad Exp $
echo "[+] Running aclocal..."
aclocal
echo "[+] Running autoheader..."
autoheader
echo "[+] Running automake..."
automake --foreign --add-missing --copy
echo "[+] Running autoconf..."
autoconf
echo " "
echo "Now, re-run ./configure"
