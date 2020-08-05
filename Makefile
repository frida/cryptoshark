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
	sudo apt install qt5-default qtdeclarative5-dev

.PHONY: build
build:
	./build

.PHONY: publish
publish:
	echo publish to be written
