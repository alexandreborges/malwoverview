#!/usr/bin/env python3
import os
from setuptools import setup, find_packages
from pathlib import Path
import platform

USER_HOME_DIR = str(Path.home()) + os.sep

with open("README.md", encoding='utf8') as readme:
    long_description = readme.read()

setup(
    name="malwoverview",
    version="7.0",
    author="Alexandre Borges",
    author_email="reverseexploit@proton.me",
    license="GNU GPL v3.0",
    url="https://github.com/alexandreborges/malwoverview",
    description=("Malwoverview is a first response tool for threat hunting."),
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(exclude=["pictures"]),
    include_package_data=True,
    python_requires=">=3.8",
    classifiers=[
    'Operating System :: OS Independent',
    'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
    'Programming Language :: Python :: 3',
    ],
    install_requires=[
        "pefile",
        "colorama",
        "python-magic; platform_system == 'Linux' or platform_system == 'Darwin'",
        "simplejson",
        "requests",
        "validators",
        "geocoder",
        "polyswarm-api",
        # Standard library in Python 3, do not force install
        # "pathlib",
        # "configparser",
		"python-magic-bin; platform_system == 'Windows'"
    ],
    entry_points = {
        "console_scripts": [
            "malwoverview = malwoverview.malwoverview:main",
        ]
    },
    # package_data should list actual files inside packages; root-level files
    # are included via include_package_data + sdist configuration if present.
    package_data={"malwoverview": []},
)
