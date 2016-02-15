#!/bin/bash

echo "Provisioning your FTP Server"

cd /tmp

echo "Downloading ProFTP Server 1.3.1"
wget http://ftp.mirrorservice.org/sites/ftp.proftpd.org/historic/source/proftpd-1.3.1.tar.bz2 > /dev/null

echo "Decompressing the package ..."
bzip2 -d proftpd-1.3.1.tar.bz2 > /dev/null 2>&1

echo "Extracting the package ..."
tar -xvf proftpd-1.3.1.tar > /dev/null 2>&1

echo "Installing and configuring the server ... Please be patient, this step may take a few moments"
cd proftpd-1.3.1
./configure -sysconfdir=/etc > /dev/null 2>&1
make > /dev/null 2>&1
make install > /dev/null 2>&1

echo "Creating symbolic link ..."
ln -s /usr/local/sbin/proftpd /usr/sbin/proftpd > /dev/null 2>&1

clear

echo "Starting FTP server now ... "
proftpd
echo "FTP server has started!"
