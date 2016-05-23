from setuptools import setup

setup(
    name='AccessControlPlugin',
    version='1.0',
    packages=['AccessControlPlugin'],
    install_requires=
    [
        'Coronado',
        'MySQLPlugin',
        'PyMySQL',
        'argh'
    ],
    author='Mukul Majmudar',
    author_email='mukul@curecompanion.com',
    description='Access control Coronado plugin')
