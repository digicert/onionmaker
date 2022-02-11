from setuptools import setup

setup(
    name='onion-maker',
    version='0.1',
    packages=['onion-maker'],
    url='https://github.com/digicert/onion-maker',
    license='MIT',
    author='DigiCert, Inc.',
    author_email='corey.bonnell@digicert.com',
    description='A utility to generate CSRs suitable for validating Onion Domain Names per Appendix B of the '
                'CA/Browser Forum Baseline Requirements ',
    install_requires=[
        'pyasn1',
        'pyasn1_alt_modules',
        'cryptography'
    ],
)
