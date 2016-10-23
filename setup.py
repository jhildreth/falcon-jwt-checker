from setuptools import setup

setup(
    name='falcon-jwt-checker',
    version='0.1.0',
    description='Falcon middleware to validate JWTs on routes.',
    author='Justin Hildreth',
    author_email='it@justinhildreth.com',
    url='https://github.com/jhildreth/falcon_jwt_checker',
    download_url='https://github.com/jhildreth/falcon_jwt_checker/tarball/0.1.0',
    license='MIT',
    packages=['falcon_jwt_checker'],
    install_requires=[
        'falcon',
        'PyJWT',
        'cryptography'
    ],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3'
    ],
    keywords=['jwt', 'falcon']
)
