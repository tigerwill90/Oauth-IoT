ENV = .env
LOGS = apache2
LIB = vendor
DB = mysql
VHOST = vhost.conf

all : clean install

help :
	@echo ""
	@echo "Available tasks :"
	@echo ""
	@echo "  all                Clean and Install Oauth2.0 server"
	@echo "  install            Install Oauth2.0 server"
	@echo "  update             Update dependencies"
	@echo "  autoload           Update autoloader"
	@echo "  fixpermission      Fix directory permission for logs"
	@echo "  bash               Run bash command inside httpd container"
	@echo "  testall            Run all testsuite"
	@echo "  testintrospection  Run introspection testsuite"
	@echo "  build              Build & run docker image"
	@echo "  clean              Clean and reset the project"
	@echo ""

install : build update fixpermission
	cp src/.env.example src/$(ENV)

travis :
	cp .env.example $(ENV)
	make virtual
	docker-compose -f docker-compose.travis.yml up --build -d
	make update
	cp src/.env.example src/$(ENV)

virtual :
	chmod +x vhost/virtualhost.sh
	vhost/./virtualhost.sh

update :
	docker-compose exec -u oauth httpd composer update --prefer-dist
	make autoload

autoload :
	docker-compose exec -u oauth httpd composer dump-autoload -o

bash :
	docker-compose exec httpd bash

fixpermission :
	chmod -R 777 src/logs

build : virtual
	docker-compose down
	docker-compose build
	docker-compose up -d

test : testintrospection

travistest :
	docker-compose exec httpd vendor/bin/phpunit --testsuite all --coverage-text --coverage-clover=coverage.xml

testintrospection :
	docker-compose exec httpd vendor/bin/phpunit --testsuite introspection
	docker-compose exec httpd vendor/bin/phpcs -p -n --standard=PSR2 --extensions=php app/services/Introspection tests/Introspection app/controllers/IntrospectionController.php

static :
	docker-compose exec httpd vendor/bin/phpstan analyse app/ tests/ --level max

clean :
	docker-compose down
	rm -rf src/$(LIB)
	rm -rf src/$(ENV)
	rm -rf vhost/$(VHOST)
	rm -rf src/composer.lock

mrproper : clean
	rm -rf logs/$(LOGS)
	rm -rf src/logs/*.log
	rm -rf db/$(DB)
	rm -rf $(ENV)