#!/usr/bin/env python2

from pip.req import parse_requirements
from setuptools import setup, find_packages
import os


def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


def requirements(requirements_file='requirements.txt'):
    reqs_from_file = parse_requirements(
        os.path.join(os.path.dirname(__file__), requirements_file),
        session=False
    )
    reqs = []
    for r in reqs_from_file:
        if r.req:
            reqs.append(str(r.req))
        # else:
        #     reqs.append(str(r.link))
    return reqs


setup(
    name='opsview',
    version='0.8.6',
    description='Opsview REST API client',
    license='GPLv3',
    long_description=read('README.md'),
    author='Philipp Schmitt',
    author_email='philipp@schmitt.co',
    url='https://github.com/pschmitt/python-opsview',
    packages=find_packages(),
    include_package_data=True,
    install_requires=requirements(),
    keywords=['opsview', 'monitoring', 'rest', 'client'],
    classifiers=[
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)'
    ]
)
