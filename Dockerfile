###
###             DOCKER LAMP STACK
###             Start new project with full stack in few minutes
###
###

FROM php:7.2.9-apache
MAINTAINER "tigerwill90" <sylvain.muller90@gmail.com>

ENV USER=www-data
ENV GROUP=www-data

ADD /src /var/www/html

###
### Install tools
###
RUN set -x \
        && apt-get update \
        && apt-get install --no-install-recommends --no-install-suggests -y \
                git \
                make \
                wget

###
### Install php extension
###
RUN set -x \
        && buildDeps=" \
                libmemcached-dev \
                zlib1g-dev \
                libgmp-dev \
                libsodium-dev \
                libcurl4-openssl-dev \
        " \
        && doNotUninstall=" \
                libmemcached11 \
                libmemcachedutil2 \
        " \
        && apt-get install -y $buildDeps --no-install-recommends \
        && rm -r /var/lib/apt/lists/* \
        \
        && docker-php-source extract \
        && git clone --branch php7 https://github.com/php-memcached-dev/php-memcached /usr/src/php/ext/memcached/ \
        && docker-php-ext-install memcached \
        && docker-php-ext-enable memcached \
        \
        && ln /usr/include/x86_64-linux-gnu/gmp.h /usr/include/ \
        && docker-php-ext-install gmp \
        && docker-php-ext-enable gmp \
        \
        && docker-php-ext-install sodium \
        && docker-php-ext-enable sodium \
        \
        && docker-php-ext-install curl \
        && docker-php-ext-enable curl \
        \
        && pecl install xdebug-2.6.1 \
        && docker-php-ext-enable xdebug \
        \
        && pecl install uopz-5.0.2 \
        && docker-php-ext-enable uopz \
        \
        && docker-php-source delete \
        && apt-mark manual $doNotUninstall \
        \
        #clean-up
        && apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false $buildDeps

###
### Install PDO
###
RUN set -x \
   && docker-php-ext-install pdo_mysql \
   && docker-php-ext-enable pdo_mysql

###
### Install composer
###
ENV COMPOSER_ALLOW_SUPERUSER=1
RUN set -x \
  && curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer \
  && composer self-update

###
### Adding custom vhost conf
###
ADD /vhost/vhost.conf /etc/apache2/sites-available

###
### Generate certificat
###
RUN openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/ssl-cert-snakeoil.key -out /etc/ssl/certs/ssl-cert-snakeoil.pem -subj "/C=AT/ST=Vienna/L=Vienna/O=Security/OU=Development/CN=example.com"

###
### Configure ssl 
###
RUN a2enmod rewrite
RUN a2ensite default-ssl
RUN a2enmod ssl

###
### Override default vhost conf
###
RUN set -x \
      # disable default vhost conf && enable custom vhost
      && a2dissite 000-default.conf \
      && a2ensite vhost.conf \
      && a2enmod rewrite

###
### Init project and fix permission
###
RUN set -x \
  && mkdir -p /var/www/html/public \
  && mkdir -p /var/www/html/logs \
  && chmod 0755 /var/www/html/public \
  && chmod -R 777 /var/www/html/logs \
  && chown -R ${USER}:${GROUP} /var/www/html

RUN service apache2 restart

VOLUME /var/www/html

EXPOSE 80
EXPOSE 443

WORKDIR /var/www/html
