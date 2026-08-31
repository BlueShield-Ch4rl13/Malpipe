"""malpipe — pipeline automatizado de análisis de malware (estático + dinámico)."""
from .pipeline import analyze, analyze_bytes

__version__ = "1.0.0"
__all__ = ["analyze", "analyze_bytes", "__version__"]
