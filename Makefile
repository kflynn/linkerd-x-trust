SHELL=bash

VERSION=0.1.0

all: cli

help:
	@echo "Just run 'make all'."
	@echo ""
	@echo "You can also 'make clean' to remove all the Docker-image stuff,"
	@echo "or 'make clobber' to smite everything and completely start over."
.PHONY: help

clean:
	-rm -f linkerd-x-trust
.PHONY: clean

clobber: clean
	true
.PHONY: clobber

# This is just an alias
cli: linkerd-x-trust

linkerd-x-trust:
	go build -o linkerd-x-trust ./cmd/
.PHONY: cmd/linkerd-x-trust

# Sometimes we have a file-target that we want Make to always try to
# re-generate (such as compiling a Go program; we would like to let
# `go install` decide whether it is up-to-date or not, rather than
# trying to teach Make how to do that).  We could mark it as .PHONY,
# but that tells Make that "this isn't a real file that I expect to
# ever exist", which has a several implications for Make, most of
# which we don't want.  Instead, we can have them *depend* on a .PHONY
# target (which we'll name "FORCE"), so that they are always
# considered out-of-date by Make, but without being .PHONY themselves.
.PHONY: FORCE
