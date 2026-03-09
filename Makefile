.PHONY: proto proto-gen proto-lint build run clean

proto: proto-lint proto-gen

proto-gen:
	buf generate

proto-lint:
	buf lint --error-format=json

build:
	go build -o bin/mini-hsm .
	chmod +x bin/mini-hsm


run: build
	HSM_MASTER_KEY=$${HSM_MASTER_KEY:-password} ./bin/mini-hsm

clean:
	rm -rf bin/ hsm_state.enc