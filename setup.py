"""Setup module for BAP IDA Python."""

from setuptools import setup, find_packages
# To use a consistent encoding
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='bap-ida-python',
    version='1.0.0~alpha',
    description='Code for interacting with IDA from BAP and vice-versa',
    long_description=long_description,
    url='https://github.com/BinaryAnalysisPlatform/bap-ida-python',
    author='Jay Bosamiya',
    author_email='jaybosamiya@acm.org',
    license='MIT',

    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2.7',
    ],

    keywords='binaryanalysis ida bap',

    packages=find_packages(),

    install_requires=[],
)
