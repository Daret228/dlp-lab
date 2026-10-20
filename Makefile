PYTHON ?= python3
export PYTHONPATH := src:.deps
.PHONY: test build demo privileged-test
build:
	mkdir -p build
	$(CC) -std=c11 -Wall -Wextra -Werror -O2 native/fanotify_launcher.c -o build/fanotify-launcher
	$(CC) -std=c11 -Wall -Wextra -Werror -O2 native/filesystem_launcher.c -o build/filesystem-gateway
test:
	$(PYTHON) -m unittest discover -s tests -v
demo:
	$(PYTHON) -m dlp.cli analyze --text 'коммерческая тайна'
privileged-test:
	DLP_RUN_GATEWAY=1 $(PYTHON) -m unittest discover -s tests -p test_gateway.py -v
