.DEFAULT_GOAL := all
.NOTPARALLEL:
.PHONY: all check test build vet race deps clean

all:
	./scripts/check all

# GNU make treats "build all" as two goals. Make build depend on all in that
# invocation, so the complete matrix is built once, without a native build first.
ifneq ($(filter all,$(MAKECMDGOALS)),)
build: all
else
build:
	./scripts/check build
endif

check:
	./scripts/check check
test:
	./scripts/check test
vet:
	./scripts/check vet
race:
	./scripts/check race
deps:
	./scripts/check deps
clean:
	rm -rf -- bin dist
