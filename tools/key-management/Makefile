
.PHONY: wheel clean venv test
binary: build_nuitka build_nuitka_converter build_nuitka_buld_devmode clean_binary_build
PYTHON3="python3.5"
MKFILE_PATH=$(abspath $(lastword $(MAKEFILE_LIST)))
PWD=$(patsubst %/,%,$(dir $(MKFILE_PATH)))
VENV=$(PWD)/venv

define clean_dist
	@echo "Clean dist directory"
	@if [ -d ./dist ]; then \
		rm -r ./dist; \
	fi
endef

define clean_nuitka_build
	@echo "Clean after nuitka build directory"
	@if [ -d ./virgil-keymanager.build ]; then \
		rm -r ./virgil-keymanager.build; \
	fi
	@if [ -d ./db_converter.build ]; then \
		rm -r ./db_converter.build; \
	fi

	@if [ -d ./db_converter.dist ]; then \
		rm -rf ./db_converter.dist; \
	fi
endef

define clean_after_wheel
	@echo "Cleaning after wheel build"
	rm -r ./build
	rm -r ./*.egg-info
endef

build_nuitka:
	nuitka --standalone --python-version=3.5 ./virgil-keymanager.py
	cp ./test_fs/_virgil_crypto_python.so ./virgil-keymanager.dist/

build_nuitka_converter:
	nuitka --standalone --python-version=3.5 ./db_converter.py
	rsync --ignore-existing ./db_converter.dist/* ./virgil-keymanager.dist/

wheel:
	${PYTHON3} setup.py bdist_wheel --universal
	$(call clean_after_wheel)

clean:
	$(call clean_after_wheel)

clean_binary_build:
	$(call clean_nuitka_build)

clean_dist:
	$(call clean_dist)

venv:
	@if [ ! -d "$(VENV)" ]; then \
		echo ">>>Creating venv at $(VENV)"; \
		python3.5 -m venv $(VENV); \
		. $(VENV)/bin/activate; \
		curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py; \
		python get-pip.py; \
		rm -f get-pip.py; \
	fi

test_requirements: venv
	@. $(VENV)/bin/activate; \
	pip install .; \
	cd ../../ext/integration_tests_framework; \
	pip install .; \
	cd -

test: test_requirements
	@. $(VENV)/bin/activate; \
	pytest -s tests
