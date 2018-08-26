ENV = .env
LOGS = apache2
DB = mysql

all : clean install

help :
	@echo ""
	@echo "Available tasks :"
	@echo ""
	@echo "  all         Clean and Install Oauth2.0 server"
	@echo "  install     Build & run docker image, install all dependancies"
	@echo "  update      Update dependancies"
	@echo "  autoload    Update autoloader"
	@echo "  build       Build & run docker image"
	@echo "  clean       Clean and reset the project"
	@echo ""

install : build update
	cp src/.env.example src/$(ENV)

update :
	docker-compose exec httpd composer update --prefer-dist
	make autoload

autoload :
	docker-compose exec httpd composer dump-autoload -o

build :
	docker-compose down
	docker-compose build
	docker-compose up -d

clean :
	docker-compose down
	rm -rf src/vendor
	rm -rf src/$(ENV)
	rm -rf src/composer.lock

mrproper : clean
	rm -rf logs/$(LOGS)
	rm -rf db/$(DB)