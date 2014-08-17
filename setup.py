from setuptools import setup, find_packages
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name = 'authkerb',
    version = '0.1',
    
    description = 'Kerberos authentication for Twisted',
    long_description = long_description,
    
    url = 'https://github.com/alexeyzotov/authkerb',
    
    author = 'Alexey Zotov',
    author_email = 'alexey.zotov@gmail.com',
    
    license = 'MIT',
    
    classifiers = [
        'Development Status :: 4 - Beta',
        'Framework :: Twisted',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 2 :: Only',
        'Topic :: Internet :: WWW/HTTP',
    ],
    
    keywords = 'twisted kerberos authentication',
    
    packages = find_packages(),
    
    install_requires = ['Twisted', 'kerberos'],
)
