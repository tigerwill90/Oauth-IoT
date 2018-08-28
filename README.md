[![Build Status](https://travis-ci.org/tigerwill90/Oauth-IoT.svg?branch=0.x)](https://travis-ci.org/tigerwill90/Oauth-IoT)
# Oauth 2.0 Server with IoT device support

### Getting started
#### Unix, make, docker & docker-compose

If you can satisfy the dependencies above, this is the easiest way to start an Oauth server

````
make install
````
#### Windows
Incoming...

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
