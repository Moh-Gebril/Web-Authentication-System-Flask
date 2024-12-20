build:
	docker compose up -d flask_db
	docker compose build

run: build
	docker compose up flask_app 

test:
	docker-compose run --rm test

stop:
	docker compose down 


clean: stop
	docker compose down --rmi all -v

