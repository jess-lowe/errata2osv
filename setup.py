from setuptools import find_packages, setup

setup(
    name="errata2osv",
    version='0.0.4',
    author="Nikita Ivanov",
    author_email="nivanov@cloudlinux.com",
    description="Tool to convert Red Hat Errata advisories to Open Source Vulnerability (OSV) database format.",
    url="https://github.com/AlmaLinux/errata2osv",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: "
        "MIT License",
        "Operating System :: OS Independent",
    ],
    packages=find_packages(),
    py_modules=['errata2osv'],
    scripts=['errata2osv.py'],
    install_requires=[
        'google-cloud-ndb>=1.12.0',
        'osv==0.0.18',
        'protobuf==3.20.0',
    ],
    python_requires=">=3.8",
)
