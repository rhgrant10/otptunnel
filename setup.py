from distutils.core import setup
import sys

setup(
    name="OTPTunnel",
    version="0.1.0",
    author="Robert Graham",
    author_email="rpgraham84@gmail.com",
    packages=["otpt", "otpt.tests"],
    scripts=["bin/otptunnel"],
    license="LICENSE",
    description="Create an encrypted tunnel interface using a one-time pad.",
    long_description=open("README.md").read()
)
