# Makefile for frida/cryptoshark
#
# 	GitHb: https://github.com/frida/cryptoshark
# 	Author: Huan LI <zixia@zixia.net> github.com/huan
#

.PHONY: all
all: install build

.PHONY: clean
clean:
	rm -fr Cryptoshark.pro.user app/agent.js app/agent/node_modules ext/frida-core

.PHONY: install
install:
	./scripts/install.sh

.PHONY: build
build:
	./build

.PHONY: publish
publish:
	echo publish to be written
