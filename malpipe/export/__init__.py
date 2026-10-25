"""Exportacion del informe a formatos de intercambio de inteligencia."""
from .misp import a_misp
from .stix import a_stix

__all__ = ["a_misp", "a_stix"]
