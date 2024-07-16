from setuptools import setup, Extension
import glob
import platform


with open('README.md', 'r', encoding='utf8') as f:
    long_description=f.read()


ed25519_ext = Extension(name='onionmaker.ed25519',
                        sources=(
                                    ['onionmaker/ed25519/ed25519-ext.c'] +
                                    glob.glob('onionmaker/ed25519/src/*.c')
                        ),
                        include_dirs=['onionmaker/ed25519/src'],
                        libraries=[lib_name for lib_name in ['advapi32'] if platform.system() == 'Windows']
                        )

setup(
    name='onionmaker',
    version='0.3',
    packages=['onionmaker'],
    url='https://github.com/digicert/onionmaker',
    license='MIT',
    author='DigiCert, Inc.',
    author_email='corey.bonnell@digicert.com',
    description='A utility to generate CSRs suitable for validating Onion Domain Names per Appendix B of the '
                'CA/Browser Forum Baseline Requirements ',
    long_description=long_description,
    long_description_content_type='text/markdown',
    install_requires=[
        'pyasn1',
        'pyasn1_alt_modules',
    ],
    ext_modules=[ed25519_ext],
    entry_points={
        'console_scripts': [
            'onionmaker = onionmaker.__main__:_main'
        ]
    }
)
