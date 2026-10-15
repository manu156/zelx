CARGO ?= cargo
CC ?= cc
CFLAGS ?= -O2 -g
PREFIX ?= /usr/local
PROFILE ?= debug
CARGO_FLAGS = --locked $(if $(filter release,$(PROFILE)),--release,)

.PHONY: all rust-build test test-runtime test-kernel check install clean
all: rust-build
rust-build:
	$(CARGO) build $(CARGO_FLAGS)
	install -Dm755 target/$(PROFILE)/zelxd build/zelxd
	install -Dm755 target/$(PROFILE)/zelxctl build/zelxctl
	install -Dm755 target/$(PROFILE)/zelx-run build/zelx-run
build:
	mkdir -p $@
build/zelx-open: tests/open_file.c | build
	$(CC) -D_GNU_SOURCE $(CFLAGS) -std=c11 -Wall -Wextra -Wpedantic -Werror $< -o $@
build/fake_fanotify.so: tests/fake_fanotify.c | build
	$(CC) -D_GNU_SOURCE $(CFLAGS) -std=c11 -Wall -Wextra -Wpedantic -Werror -pthread -fPIC -shared $< -o $@
test: all
	$(CARGO) test --locked
	python3 tests/test_cli.py
test-runtime: all build/zelx-open build/fake_fanotify.so
	ZELX_SIMULATED=1 python3 tests/test_kernel.py
test-kernel:
	@if [ "$$(id -u)" -eq 0 ]; then \
		echo 'Run make test-kernel without sudo: it builds as your user, then elevates only the Python tests.' >&2; \
		exit 2; \
	fi
	$(MAKE) all build/zelx-open
	sudo env ZELX_SIMULATED=0 python3 tests/test_kernel.py
check:
	$(CARGO) fmt --check
	$(CARGO) clippy --locked --all-targets -- -D warnings
install: all
	install -Dm755 build/zelxd $(DESTDIR)$(PREFIX)/bin/zelxd
	install -Dm755 build/zelxctl $(DESTDIR)$(PREFIX)/bin/zelxctl
	install -Dm755 build/zelx-run $(DESTDIR)$(PREFIX)/bin/zelx-run
	install -Dm644 config/default-policy.toml $(DESTDIR)/etc/zelx/default-policy.toml
clean:
	$(CARGO) clean
	rm -rf build
