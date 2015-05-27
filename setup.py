from distutils.core import setup
setup(
    name = 'idalink',
    description = 'An interface to the insides of IDA!',
    version = '0.10',
    packages = ['idalink', 'idalink.rpyc', 'idalink.rpyc.core', 'idalink.rpyc.scripts', 'idalink.rpyc.utils', 'idalink.rpyc.lib'],
    package_data = { 'idalink': [ 'support/*.sh' ] },
    install_requires=['rpyc']
)
