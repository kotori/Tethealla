#!/bin/sh

INTERNAL_IP=`tail -n 1 /etc/hosts | awk '{print $1}'`
EXTERNAL_IP=`curl -sL ipv4.icanhazip.com`

echo "External Address: $EXTERNAL_IP"
echo "Internal Address: $INTERNAL_IP"

echo "Setting up ship.ini"
sed -i.orig "s/REPLACE_ME_EXT_SHIP/${EXTERNAL_IP}/g" ship.ini
sed -i "s/REPLACE_ME_INT_SHIP/${INTERNAL_IP}/g" ship.ini

echo "Setting up tethealla.ini"
sed -i.orig "s/REPLACE_ME_EXT_TETH/${EXTERNAL_IP}/g" tethealla.ini
sed -i "s/REPLACE_ME_INT_TETH/${INTERNAL_IP}/g" tethealla.ini

touch ip.updated
