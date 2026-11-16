"""Point d'entrée public pour générer atomiquement les quatre configurations CyGIL."""

from .bundle import CompilationBundle, compile_bundle

__all__ = ["CompilationBundle", "compile_bundle"]
