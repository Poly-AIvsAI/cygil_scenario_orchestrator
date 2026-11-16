"""Expose les adaptateurs publics sans imposer d'implémentation VMware réelle."""

from .dry_run import DryRunAdapter
from .vagrant import render_vagrantfile

__all__ = ["DryRunAdapter", "render_vagrantfile"]
