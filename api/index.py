import os
import sys

# Make the project root importable when Vercel runs this file as a function.
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app1 import app  # noqa: E402,F401  (Vercel looks for `app`)

__all__ = ['app']
