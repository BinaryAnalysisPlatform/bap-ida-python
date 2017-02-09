#!/usr/bin/env python2.7

from setuptools import setup

setup(
    name='bap-ida-python',
    version='1.2.0',
    description='BAP IDA Plugin',
    author='BAP Team',
    url='https://github.com/BinaryAnalysisPlatform/bap-ida-python',
    maintainer='Ivan Gotovchits',
    maintainer_email='ivg@ieee.org',
    license='MIT',
    package_dir={'': 'plugins'},
    packages=['bap', 'bap.utils', 'bap.plugins'],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: MIT License',
        'Topic :: Software Development :: Disassemblers',
        'Topic :: Security'
    ]
)
