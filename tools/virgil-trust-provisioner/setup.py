from virgil_trust_provisioner import __version__, __author__
from setuptools import setup, find_packages

setup(
    name="virgil_trust_provisioner",
    version=__version__,
    packages=find_packages(exclude=('tests',)),
    install_requires=[
        'virgil-sdk==5.2.1',
        'virgil-crypto>=3,<4',
        'prettytable',
        'pyasn1',
        'psutil',
        'tinydb'
    ],
    entry_points={
        'console_scripts':
            [
                'virgil-trust-provisioner = virgil_trust_provisioner.__main__:main'
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
    description="Virgil Trust Provisioner cli",
    long_description="Virgil Trust Provisioner cli",
)
