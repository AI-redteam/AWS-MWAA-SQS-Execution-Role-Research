from setuptools import setup, find_packages

setup(
    name="celerystrike",
    version="2.0.0",
    description="AWS MWAA execution role exploitation toolkit — C2 via SQS",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "boto3>=1.28.0",
    ],
    entry_points={
        "console_scripts": [
            "celerystrike=celerystrike.cli:main",
        ],
    },
)
