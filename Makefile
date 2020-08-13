.PHONY: test ctest covdir coverage linter qtest clean dep release info build
APP_VERSION:=$(shell cat VERSION | head -1)
GIT_COMMIT:=$(shell git describe --dirty --always)
GIT_BRANCH:=$(shell git rev-parse --abbrev-ref HEAD -- | head -1)
BUILD_USER:=$(shell whoami)
BUILD_DATE:=$(shell date +"%Y-%m-%d")
BUILD_GOOS:=$(shell go version | cut -d" " -f4 | cut -d"/" -f1)
BUILD_GOARCH:=$(shell go version| cut -d" " -f4 | cut -d"/" -f2)
PLUGIN_PKGS:="firewall" "portmap"
#PLUGIN_PKGS:="portmap"
#PLUGIN_PKGS:="firewall"
PLUGINS:="cni-nftables-firewall" "cni-nftables-portmap"
#PLUGINS:="cni-nftables-portmap"
#PLUGINS:="cni-nftables-firewall"
VERBOSE:=-v
ifdef TEST
	TEST:="-run ${TEST}"
endif

all: info build

info:
	@echo "Version: $(APP_VERSION), Branch: $(GIT_BRANCH), Revision: $(GIT_COMMIT)"
	@echo "Build on $(BUILD_DATE) by $(BUILD_USER)"
	@echo "$(shell go version)"
	@echo "go os/arch: $(BUILD_GOOS)/$(BUILD_GOARCH)"

build:
	@rm -rf bin/*
	@mkdir -p bin/
	@for PLUGIN in $(PLUGINS);do\
		for GOOS in linux;do\
			for GOARCH in amd64; do\
				BINARY=$${PLUGIN}.$${GOOS}-$${GOARCH};\
				echo "building $${BINARY} ...";\
				CGO_ENABLED=0 GOOS=$${GOOS} GOARCH=$${GOARCH} \
				go build -v -o bin/$${BINARY} $(VERBOSE) \
				-ldflags="-w -s \
				-X main.gitBranch=$(GIT_BRANCH) \
				-X main.gitCommit=$(GIT_COMMIT) \
				-X main.buildUser=$(BUILD_USER) \
				-X main.buildDate=$(BUILD_DATE)" \
				-gcflags="all=-trimpath=$(GOPATH)/src" \
				-asmflags="all=-trimpath $(GOPATH)/src" ./cmd/$${PLUGIN}/*.go;\
				chmod +x bin/$${BINARY};\
			done ;\
		done ;\
	done
	@for PLUGIN in $(PLUGINS);do\
		./bin/$${PLUGIN}.$(BUILD_GOOS)-$(BUILD_GOARCH) --version;\
	done
	@echo "Done!"

linter:
	@echo "Running lint checks"
	@for PLUGIN in cni-nftables-firewall cni-nftables-portmap;do\
		echo "$@: $${PLUGIN}";\
		golint -set_exit_status cmd/$${PLUGIN}/*;\
	done
	@for PKG in $(PLUGIN_PKGS) "utils"; do\
		echo "$@: $${PKG}";\
		golint -set_exit_status pkg/$${PKG}/*.go;\
	done
	@echo "PASS: golint"

test: linter
	@rm -rf .coverage
	@for PKG in $(PLUGIN_PKGS); do\
		mkdir -p .coverage/pkg/$${PKG};\
		rm -rf ./pkg/$${PKG}/$${PKG}.test;\
		go test -c $(VERBOSE) -coverprofile=.coverage/pkg/$${PKG}/coverage.out ./pkg/$${PKG};\
		mv ./$${PKG}.test ./pkg/$${PKG}/$${PKG}.test;\
		chmod +x ./pkg/$${PKG}/$${PKG}.test;\
		sudo ./pkg/$${PKG}/$${PKG}.test -test.v -test.testlogfile ./.coverage/pkg/$${PKG}/test.log \
			-test.coverprofile ./.coverage/pkg/$${PKG}/$${PKG}_coverage.out;\
	done

ctest: covdir linter
	@richgo version || go get -u github.com/kyoh86/richgo
	@time richgo test $(VERBOSE) $(TEST) -coverprofile=.coverage/coverage.out ./*.go

covdir:
	@echo "Creating .coverage/ directory"
	@mkdir -p .coverage

coverage:
	@#go tool cover -help
	@for PKG in $(PLUGIN_PKGS);do\
		echo "Creating coverage for $${PKG}";\
		go tool cover -html=.coverage/pkg/$${PKG}/$${PKG}_coverage.out -o .coverage/pkg/$${PKG}/$${PKG}_coverage.html;\
		go tool cover -func=.coverage/pkg/$${PKG}/$${PKG}_coverage.out | grep -v "100.0";\
	done

clean:
	@rm -rf .doc
	@rm -rf .coverage
	@rm -rf bin/

qtest:
	@echo "Perform quick tests ..."
	@#go test -v -run TestVersioned *.go

dep:
	@echo "Making dependencies check ..."
	@go get -u golang.org/x/lint/golint
	@go get -u github.com/greenpau/versioned/cmd/versioned

release:
	@echo "Making release"
	@go mod tidy
	@go mod verify
	@if [ $(GIT_BRANCH) != "main" ]; then echo "cannot release to non-main branch $(GIT_BRANCH)" && false; fi
	@git diff-index --quiet HEAD -- || ( echo "git directory is dirty, commit changes first" && false )
	@versioned -patch
	@git add VERSION
	@git commit -m 'updated VERSION file'
	@./bin/$(BINARY) -sync cmd/$(BINARY)/main.go
	@for PLUGIN in cni-nftables-firewall cni-nftables-portmap;do\
		versioned -sync cmd/$${PLUGIN}/main.go
	done
	@echo "Patched version"
	@git add .
	@git commit -m "released v`cat VERSION | head -1`"
	@git tag -a v`cat VERSION | head -1` -m "v`cat VERSION | head -1`"
	@git push
	@git push --tags
	@echo "If necessary, run the following commands:"
	@echo "  git push --delete origin v$(APP_VERSION)"
	@echo "  git tag --delete v$(APP_VERSION)"

deploy:
	@sudo mkdir -p /usr/local/lib/cni
	@for PLUGIN in $(PLUGINS);do\
		sudo rm -rf /usr/local/lib/cni/$${PLUGIN};\
		sudo cp ./bin/$${PLUGIN}.$(BUILD_GOOS)-$(BUILD_GOARCH) /usr/local/lib/cni/$${PLUGIN};\
	done

