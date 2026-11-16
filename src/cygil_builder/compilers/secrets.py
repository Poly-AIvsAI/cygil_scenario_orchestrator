"""Résolution volontaire des secrets pour distinguer scénario portable et copie déployable."""

from __future__ import annotations

import os


def secret_value(
    reference: str | None,
    inject: bool,
    secret_values: dict[str, str] | None = None,
) -> str:
    """Résout un secret sans jamais émettre de marqueur ``${VARIABLE}``.

    Une copie non injectée contient une chaîne vide. Pour une copie de
    déploiement, le coffre local fourni est prioritaire puis l'environnement est
    consulté. Un secret non disponible reste vide afin que les autres champs du
    document demeurent éditables sans exposer une pseudo-valeur trompeuse.
    """
    if not reference:
        return ""
    if not inject:
        return ""
    if secret_values and reference in secret_values:
        return secret_values[reference]
    return os.getenv(reference, "")
