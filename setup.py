from setuptools import setup, find_packages

setup(
    name='idalink',
    description='An interface to the insides of IDA!',
    long_description=open('README.md').read(),
    version='0.10',
    url='https://github.com/zardus/idalink',
    license='GNU General Public License v3',
    packages=find_packages(),
    package_data={
        'idalink': ['support/*'],
    },
    install_requires=[
        'rpyc',
    ],
)
