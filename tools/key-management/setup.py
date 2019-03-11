from soraa_keymanager import __version__, __author__
from setuptools import setup, find_packages

setup(
    name="soraa-keymanager",
    version=__version__,
    packages=find_packages(),
    install_requires=[
        'virgil-sdk>=4.2.0,<5',
        'virgil-crypto>=2.0.4,<3',
        'prettytable',
        'pyasn1',
        'pycups',
        'PyCRC',
        'psutil',
        'tinydb'
    ],
    package_data={
        "soraa_keymanager": [
            "external_utils/util/origin/soraa-dongles-cli",
            "external_utils/util/emulator/soraa-dongles-cli"
        ],
    },
    entry_points={
        'console_scripts':
            [
                'keymanager = soraa_keymanager.__main__:main',
                'dbconverter = soraa_keymanager.__main__:converter_main'
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
    description="Soraa key manager cli",
    long_description="Soraa key manager cli",
)
