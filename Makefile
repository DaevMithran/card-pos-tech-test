.PHONY: proto proto-gen proto-lint

proto: proto-lint proto-gen

proto-gen:
	buf generate

proto-lint:
	buf lint --error-format=json