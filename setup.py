from setuptools import setup, Extension
import glob
import platform


ed25519_ext = Extension(name='ed25519',
                        sources=['onion-maker/ed25519-ext.c'] + glob.glob('ed25519/src/*.c'),
                        include_dirs=['ed25519/src'],
                        libraries=[lib_name for lib_name in ['advapi32'] if platform.system() == 'Windows']
                        )

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
    ],
    ext_modules=[ed25519_ext]
)
