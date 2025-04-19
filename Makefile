.PHONY: dep
dep:
	pipx install pre-commit

.PHONY: init
init:
	pre-commit install
	cargo deny fetch
	cargo b

.PHONY: test
test:
	@cargo nextest run --all-features --examples

.PHONY: release
release: test
	@cargo release tag --execute
	@git cliff -o CHANGELOG.md
	@git commit -a -n -m "Update CHANGELOG.md" || true
	@git push origin master
	@cargo release push --execute

.PHONY: update-submodule
update-submodule:
	@git submodule update --init --recursive --remote
