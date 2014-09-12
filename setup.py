from distutils.core import setup
import sys

setup(
    name="OTP Tunnel",
    version="0.1.0",
    author="Robert Graham",
    author_email="rpgraham84@gmail.com",
    packages=["otpt"],
    scripts=["bin/otptunnel"],
    url="http://pypi.python.org/pypi/OTPTunnel",
    license="LICENSE",
    description="Create an enrypted tunnel interface using a one-time pad.",
    long_description=open("README.md").read()
)
