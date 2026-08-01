.PHONY: install demo diff config clean help

help:
	@echo "Lfuzzer make targets:"
	@echo "  install  - pip install -r requirements.txt"
	@echo "  demo     - run generators + logger __main__ demos"
	@echo "  diff     - run the gold-vs-BFD differential suite"
	@echo "  config   - print resolved tool/loader paths (lfuzzer.config)"
	@echo "  clean    - remove __pycache__ and *.pyc"

install:
	pip install -r requirements.txt

demo:
	python -m lfuzzer.generators.generators
	python -m lfuzzer.logger.logger

diff:
	cd lfuzzer/differential/exp_goldbfd_diff && bash run_all.sh

config:
	python -m lfuzzer.config

clean:
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	find . -type f -name '*.pyc' -delete
