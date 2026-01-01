from setuptools import setup, find_packages

setup(
    name="nebulashield-infra",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "aws-cdk-lib>=2.130.0",
        "constructs>=10.0.0",
    ],
    python_requires=">=3.9",
)