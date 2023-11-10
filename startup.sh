#!/bin/bash

sed -i s/__LISTEN_PORT__/$1/g /etc/apache2/ports.conf
sed -i s/__LISTEN_PORT__/$1/g /etc/apache2/sites-available/000-default.conf

apachectl -D FOREGROUND
