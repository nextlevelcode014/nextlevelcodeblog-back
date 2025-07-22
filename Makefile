DOCKER_COMPOSE = docker compose
SQLX = sqlx

.PHONY: help up-dev up-dev-b up-prod up-prod-b test down down-v down-orphans

help:
	@echo "Usage:"
	@echo "  make up-dev        Start services in dev (mode detached)"
	@echo "  make up-dev-b      Start services in dev and rebuild (mode detached)"
	@echo "  make up-prod       Start services in prod (mode detached)"
	@echo "  make up-prod-b     Start services in prod and rebuild (mode detached)"
	@echo "  make test          Run all tests and down services"
	@echo "  make down          Down services"
	@echo "  make down-v        Down services and clean volumes"
	@echo "  make down-orphans  Remove orphaned services"

up-dev:
	${DOCKER_COMPOSE} -f docker-compose-dev.yml up -d

up-dev-b:
	${DOCKER_COMPOSE} -f docker-compose-dev.yml up --build -d

up-prod:
	${DOCKER_COMPOSE} -f docker-compose-prod.yml up -d

up-prod-b:
	${DOCKER_COMPOSE} -f docker-compose-prod.yml up --build -d

test:
	${DOCKER_COMPOSE} -f docker-compose-dev.yml up -d
	@echo "Waiting for container 'api' to be ready..."
	@until docker exec api cargo check > /dev/null 2>&1; do \
		echo "Still waiting..."; \
		sleep 2; \
	done
	@echo "Running tests..."
	docker exec api cargo test
	${DOCKER_COMPOSE} -f docker-compose-dev.yml down -v

down:
	${DOCKER_COMPOSE} -f docker-compose-prod.yml down

down-v:
	${DOCKER_COMPOSE} -f docker-compose-prod.yml down -v

down-orphans:
	${DOCKER_COMPOSE} down -v --remove-orphans
