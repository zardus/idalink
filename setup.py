from setuptools import setup, find_packages

setup(
    name='idalink',
    description='An interface to the insides of IDA!',
    long_description=open('README.md').read(),
    version='0.12',
    url='https://github.com/zardus/idalink',
    license='GNU General Public License v3',
    author='Zardus',
    author_email='zardus@gmail.com',
    maintainer='rhelmot',
    maintainer_email='audrey@rhelmot.io',
    packages=find_packages(),
    install_requires=[
        'rpyc',
    ],
)
