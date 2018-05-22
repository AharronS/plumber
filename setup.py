import os
from setuptools import setup


def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


setup(
    name="Plumber",
    version="1.0",
    author="Aharon Shenvald",
    author_email="aharron@gmail.com",
    description=("tunnel data via socks over ICMP"),
    license="BSD",
    keywords="",
    url="",
    install_requires=['scapy', 'colorama'],
    packages=['plumber'],
    long_description=read('README'),
    classifiers=[],
)