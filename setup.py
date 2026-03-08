import sys
from setuptools import setup, Extension
import pybind11

ext_modules = [
    Extension(
        "sentinel_engine_cpp",
        ["sentinel_engine.cpp"],
        include_dirs=[pybind11.get_include()],
        language="c++",
        extra_compile_args=["-std=c++17", "-O3"],
        extra_link_args=["-static", "-static-libgcc", "-static-libstdc++"],
    ),
]

setup(
    name="sentinel_engine_cpp",
    version="1.0",
    description="High performance SentinelGate pipeline",
    ext_modules=ext_modules,
)
