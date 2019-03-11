
.PHONY: wheel clean
binary: build_nuitka build_nuitka_converter build_nuitka_buld_devmode clean_binary_build
PYTHON3="python3.5"

define clean_dist
	@echo "Clean dist directory"
	@if [ -d ./dist ]; then \
		rm -r ./dist; \
	fi
endef

define clean_nuitka_build
	@echo "Clean after nuitka build directory"
	@if [ -d ./soraa-keymanager.build ]; then \
		rm -r ./soraa-keymanager.build; \
	fi
	@if [ -d ./db_converter.build ]; then \
		rm -r ./db_converter.build; \
	fi
	@if [ -d ./bulb_devmode.build ]; then \
		rm -rf ./bulb_devmode.build; \
	fi

	@if [ -d ./db_converter.dist ]; then \
		rm -rf ./db_converter.dist; \
	fi
	@if [ -d ./bulb_devmode.dist ]; then \
		rm -rf ./bulb_devmode.dist; \
	fi
endef

define clean_after_wheel
	@echo "Cleaning after wheel build"
	rm -r ./build
	rm -r ./*.egg-info
endef

build_nuitka:
	nuitka --standalone --python-version=3.5 ./soraa-keymanager.py
	cp ./test_fs/_virgil_crypto_python.so ./soraa-keymanager.dist/

build_nuitka_converter:
	nuitka --standalone --python-version=3.5 ./db_converter.py
	rsync --ignore-existing ./db_converter.dist/* ./soraa-keymanager.dist/

build_nuitka_buld_devmode:
	nuitka --standalone --python-version=3.5 ./bulb_devmode.py
	rsync --ignore-existing ./bulb_devmode.dist/* ./soraa-keymanager.dist/

wheel:
	${PYTHON3} setup.py bdist_wheel --universal
	$(call clean_after_wheel)

clean:
	$(call clean_after_wheel)

clean_binary_build:
	$(call clean_nuitka_build)

clean_dist:
	$(call clean_dist)