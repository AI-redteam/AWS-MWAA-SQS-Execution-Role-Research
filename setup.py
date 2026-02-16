from setuptools import setup, find_packages

setup(
    name="mwaa-security-tool",
    version="2.0.0",
    description="AWS MWAA SQS Execution Role Security Testing Tool",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "boto3>=1.28.0",
    ],
    entry_points={
        "console_scripts": [
            "mwaa-security-tool=mwaa_security_tool.cli:main",
        ],
    },
)
