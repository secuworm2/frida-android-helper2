from setuptools import setup

with open("requirements.txt", encoding="utf-8") as f:
    requirements = [line.strip() for line in f if line.strip()]


setup(
    name="frida-android-helper",
    description="Handy Android frida helping tools at the tip of your terminal",
    version="0.7.1",
    packages=["frida_android_helper"],
    package_data={"frida_android_helper": ["frida_hooks/*.js", "scripts/*"]},
    install_requires=requirements,
    zip_safe=True,
    license="MIT",
    keywords="frida android helper",
    entry_points={
        'console_scripts': [
            'fah = frida_android_helper.fah:main'
        ]
    },
)
