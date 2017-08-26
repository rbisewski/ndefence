# Version
VERSION = `date +%y.%m`

# If unable to grab the version, default to N/A
ifndef VERSION
    VERSION = "n/a"
endif

#
# Makefile options
#


# State the "phony" targets
.PHONY: all clean build install uninstall


all: build

build:
	@go build -ldflags '-s -w -X main.Version='${VERSION}

clean:
	@go clean

install: build
	@echo installing executable file to /usr/bin/ndefence
	@sudo cp ndefence /usr/bin/ndefence
	@echo installing cron file to /etc/cron.d/ndefence
	@sudo cp ndefence.cron /etc/cron.d/ndefence

uninstall: clean
	@echo removing executable file from /usr/bin/ndefence
	@sudo rm /usr/bin/ndefence
	@echo removing cron file from /etc/cron.d/ndefence
	@sudo rm /etc/cron.d/ndefence
