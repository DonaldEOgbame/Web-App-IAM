# ml_pipeline/common/__init__.py
"""
Shared utilities for ml_pipeline (e.g., calibration wrappers).
Avoid importing heavy submodules here to keep package imports fast/safe.
"""

__all__ = ["calibration"]
