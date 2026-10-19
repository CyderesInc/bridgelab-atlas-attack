.PHONY: setup test crosswalk navigator attack lab-up lab-down demo clean

setup:
	pip install -e ".[dev]"

test:
	pytest tests/ -v

crosswalk:
	bridgelab-crosswalk --output output/

navigator:
	bridgelab-navigator --output output/

attack:
	bridgelab-attack --mode mock

lab-up:
	docker compose up -d

lab-down:
	docker compose down -v

demo: lab-up
	@echo "Waiting for services..."
	@sleep 15
	bridgelab-attack --mode live
	$(MAKE) lab-down

clean:
	rm -rf output/*.json output/*.csv
