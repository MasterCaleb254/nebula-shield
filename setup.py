from setuptools import setup, find_packages

setup(
    name="nebula-shield",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "boto3>=1.34.0",
        "aws-cdk-lib>=2.130.0",
        "constructs>=10.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-mock>=3.11.0",
            "black>=23.0.0",
            "mypy>=1.0.0",
            "python-dotenv>=1.0.0",
            "freezegun>=1.2.0",
        ],
    },
    python_requires=">=3.9",
)
