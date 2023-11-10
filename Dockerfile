FROM debian:latest

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get upgrade -y
RUN apt install ca-certificates libnss-ldap libpam-ldap ldap-utils libssl-dev libnet-ldap-perl libterm-readkey-perl libcrypt-jwt-perl gnupg2 libldap2-dev libsasl2-dev libcurl4-openssl-dev build-essential zlib1g-dev libncurses5-dev libgdbm-dev libnss3-dev libsqlite3-dev libreadline-dev libffi-dev libbz2-dev gnutls-bin ssl-cert -y
RUN apt install nano curl apache2 libapache2-mod-perl2 libcache-fastmmap-perl libjson-perl -y libapache2-request-perl -y
RUN ln -s /etc/apache2/mods-available/ssl.load /etc/apache2/mods-enabled/ && ln -s /etc/apache2/mods-available/ssl.conf /etc/apache2/mods-enabled/ && ln -s /etc/apache2/mods-available/proxy.load /etc/apache2/mods-enabled/ && ln -s /etc/apache2/mods-available/proxy.conf /etc/apache2/mods-enabled/ && ln -s /etc/apache2/mods-available/socache_shmcb.load /etc/apache2/mods-enabled/ && ln -s /etc/apache2/mods-available/headers.load /etc/apache2/mods-enabled/ && ln -s /etc/apache2/mods-available/proxy_http.load /etc/apache2/mods-enabled/
ADD ports.conf /etc/apache2/ports.conf
ADD index.html /var/www/html/index.html
ADD 000-default.conf /etc/apache2/sites-available/000-default.conf
RUN mv /etc/apache2/sites-enabled/000-default.conf /tmp/000-default.confORIG
RUN ln -s /etc/apache2/sites-available/000-default.conf /etc/apache2/sites-enabled/
ADD perl_mods /perl_mods
ADD startup.sh /startup.sh
CMD /startup.sh 8443