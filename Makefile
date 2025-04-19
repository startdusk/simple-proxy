.PHONY: dep
dep:
	pipx install pre-commit

.PHONY: init
init:
	pre-commit install
	cargo deny fetch
	cargo b
