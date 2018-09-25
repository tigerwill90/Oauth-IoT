[![Build Status](https://travis-ci.org/tigerwill90/Oauth-IoT.svg?branch=0.x)](https://travis-ci.org/tigerwill90/Oauth-IoT)
[![codecov](https://codecov.io/gh/tigerwill90/Oauth-IoT/branch/0.x/graph/badge.svg)](https://codecov.io/gh/tigerwill90/Oauth-IoT)
# Oauth 2.0 Server with IoT device support

### Getting started
#### Unix system

If you can satisfy the dependencies below, this is the easiest way to start an Oauth server

- Unix system
- make
- docker
- docker-compose
- git

Rename .env.example file to .env in racine folder

````
git clone  https://github.com/tigerwill90/Oauth-IoT.git
cd Oauth-IoT
cp .env.exemple .env
make install
````
Server will start automatically !

### Tests

* Unit test : phpunit
* PSR-1 & PSR-2 : phpcs
* static analyser : phpstan

you have the choice to run tests by groups. 
You can use `make help` to see all test command available

````
make test
make static
````

### Reset
You can reset the whole project with `make clean` (without logs and db) or `make mrproper`

### Version
v0.5-dev
