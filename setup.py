from distutils.core import setup
setup(
    name = 'idalink',
    version = '0.01',
    packages = ['idalink', 'idalink.rpyc'],
    package_data = { 'idalink': [ 'support/*.sh' ] },
    install_requires=[i.strip() for i in open('requirements.txt').readlines() if 'git' not in i]
)
