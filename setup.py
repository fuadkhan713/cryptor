from setuptools import setup, find_packages

def main():
    README = open('README.md').read()
    setup(
        name="filecrypter",
        version="3.10",
        url='https://github.com/fuadkhan713/filecrypter',
        license='',
        author="Fuad Khan",
        author_email='fuad.khan713@gmail.com',
        description='Script to Help Encrypt and Decrypt File Using RSA Key.',
        long_description=README,
        long_description_content_type='text/markdown',
        classifiers=[
            'Development Status :: 4 - Beta',
            'Intended Audience :: Education',
            'Programming Language :: Python :: 3.7',
            'Programming Language :: Python :: 3.8',
            'Programming Language :: Python :: 3.9',
            'Topic :: Security :: Cryptography ',
            'Topic :: System :: Networking',

        ],
        install_requires=['pycryptodome', 'torpy', 'flask', 'requests', 'urllib3'],
        py_modules=["filecrypter"],
        python_requires='>=3.7',
        project_urls={
            'Documentation': 'https://packaging.python.org/tutorials/distributing-packages/',
            'Funding': 'https://donate.pypi.org',
            'Source': 'https://github.com/fuadkhan713/filecrypter',
            'Tracker': 'https://github.com/fuadkhan713/filecrypter/issues',
        },
        packages=find_packages(),
        entry_points={
            'console_scripts': [
                'filecrypter=filecrypter:main',
            ],
        },

    )


if __name__ == '__main__':
    main()
