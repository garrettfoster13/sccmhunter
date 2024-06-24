#!/usr/bin/env python
import os
from setuptools import setup

from lib.scripts.banner import __version__

PACKAGE_NAME = "sccmhunter"

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name=PACKAGE_NAME,
    version=__version__,
    description="SCCMHunter is a post-ex tool built to streamline identifying, profiling, and attacking SCCM related assets in an Active Directory domain.",
    author="Garrett Foster",
    license="MIT",
    long_description=read('README.md'),
    long_description_content_type="text/markdown",
    platforms=["Unix"],
    scripts=["sccmhunter.py"],
    install_requires=["cmd2>=2.4.3","cryptography>=38.0.4","impacket>=0.11.0","ldap3>=2.9.1","pandas>=1.5.3","pyasn1>=0.4.8","pyasn1_modules>=0.3.0","Requests>=2.31.0","requests_ntlm>=1.1.0","requests_toolbelt>=1.0.0","rich>=13.7.0","tabulate>=0.8.9","typer>=0.9.0","urllib3>=1.26.18","pyopenssl>=23.2.0","pycryptodome>=3.18.0","numpy>=1.26.4"],
    classifiers=[
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.6",
    ]
)