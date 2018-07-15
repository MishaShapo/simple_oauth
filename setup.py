import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="simple_oauth",
    version="0.0.1",
    author="Michail Shaposhnikov",
    author_email="michailpshaposhnikov@gmail.com",
    description="Easily access OAuth protected APIs in Python",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/MishaShapo/simple_oauth",
    keywords="simple easy API oauth authentication",
    license="MIT",
    packages=setuptools.find_packages(),
    zip_safe=False,
    include_package_data=True,
    install_requires=[
      'cryptography',
      'requests_oauthlib',
      'requests',
      'Flask'
    ],
    classifiers=(
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ),
)
