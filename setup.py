from setuptools import setup

setup(
    name='falcon-jwt-checker',
    version='0.1.3',
    description='Falcon middleware to validate JWTs on routes.',
    author='Justin Hildreth',
    author_email='justin@justinhildreth.com',
    url='https://github.com/jhildreth/falcon-jwt-checker',
    download_url='https://github.com/jhildreth/falcon-jwt-checker/tarball/0.1.3',
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
