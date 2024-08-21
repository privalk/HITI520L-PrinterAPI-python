import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="hitil520-printer-api-py",
    version="0.0.1",
    author="ppiiko",
    author_email="291863911@qq.com",
    description="Printer API",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/privalk/HITI520L-PrinterAPI-python",
    project_urls={
        "Printer API": "https://github.com/privalk/HITI520L-PrinterAPI-python/issues",
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Natural Language :: Chinese (Simplified)",
    ],
    package_dir={"": "src"},
    packages=setuptools.find_packages(where="src"),
    python_requires=">=3.6",
)
