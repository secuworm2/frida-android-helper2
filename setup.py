from setuptools import setup

with open("requirements.txt", encoding="utf-8") as f:
    requirements = [line.strip() for line in f if line.strip()]

with open("readme.md", encoding="utf-8") as f:
    long_description = f.read()


setup(
    name="fah2",
    description="Handy Android frida helping tools at the tip of your terminal",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/secuworm2/frida-android-helper2",
    version="0.83",
    packages=["frida_android_helper"],
    package_data={"frida_android_helper": ["frida_hooks/*.js", "scripts/*", "tools/*"]},
    install_requires=requirements,
    python_requires=">=3.8",
    zip_safe=False,
    license="MIT",
    keywords="frida android helper",
    entry_points={
        'console_scripts': [
            'fah = frida_android_helper.fah:main',
            'fah2 = frida_android_helper.fah:main',
        ]
    },
)
