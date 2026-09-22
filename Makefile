.PHONY: env test run

env:
	./scripts/setup_env.sh

test:
	python3 -m unittest discover -v

run:
	python3 main.py
