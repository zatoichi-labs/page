init:
	pip install -r requirements.txt

build:
	echo "nightly" > rust-toolchain
	maturin develop
	rm rust-toolchain

test: build
	pytest

PYPI_TOKEN = $(shell grep -oP "password = \K.*" ~/.pypirc)
PYPI_LOGIN =--username __token__ --password $(PYPI_TOKEN)

publish:
	echo "nightly" > rust-toolchain
	maturin publish -i python3.6 $(MATURIN_ARGS) $(PYPI_LOGIN)
	rm rust-toolchain

clean:
	cargo clean
	rm -rf .pytest_cache
	rm -rf tests/__pycache__
