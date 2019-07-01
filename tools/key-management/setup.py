from virgil_keymanager import __version__, __author__
from setuptools import setup, find_packages

setup(
    name="virgil-keymanager",
    version=__version__,
    packages=find_packages(exclude=('tests',)),
    install_requires=[
        'virgil-sdk>=5,<6',
        'virgil-crypto>=3,<4',
        'prettytable',
        'pyasn1',
        'pycups',
        'PyCRC',
        'psutil',
        'tinydb'
    ],
    package_data={
        "virgil_keymanager": [
            "external_utils/util/origin/dongles-cli",
            "external_utils/util/emulator/dongles-cli"
        ],
    },
    entry_points={
        'console_scripts':
            [
                'keymanager = virgil_keymanager.__main__:main',
                'dbconverter = virgil_keymanager.__main__:converter_main'
            ]
    },
    author=__author__,
    author_email="support@virgilsecurity.com",
    url="https://virgilsecurity.com/",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "License :: OSI Approved :: BSD License",
        "Natural Language :: English",
        "Programming Language :: Python :: 3.5",
        "Topic :: Security :: Cryptography",
        ],
    license="BSD",
    description="Virgil key manager cli",
    long_description="Virgil key manager cli",
)
