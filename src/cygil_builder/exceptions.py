"""Exceptions métier partagées pour présenter des erreurs compréhensibles à l'utilisateur."""


class ScenarioError(Exception):
    """Base exception for scenario processing."""


class ScenarioValidationError(ScenarioError):
    """Raised when a scenario cannot safely be processed."""


class CompilationError(ScenarioError):
    """Raised when CyGIL configuration generation fails."""


class AdapterError(ScenarioError):
    """Raised by infrastructure and guest adapters."""
