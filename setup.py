import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="papr",  # Replace with your own username
    version="0.0.1",
    author="Patrik Kron, Wilmer Nilsson",
    author_email="{dic15pkr,dat15wni}@student.lu.se",
    description="Publicly Auditable Privacy Revocation",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/wlmr/papr",
    project_urls={
        # Bug Tracker": "https://github.com/pypa/sampleproject/issues"
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)"
        "Operating System :: OS Independent",
    ],
    packages=setuptools.find_packages(),
    python_requires='>=3.9',
)
