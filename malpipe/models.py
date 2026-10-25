"""Modelos de datos del pipeline. Dataclasses serializables a JSON."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class Hashes:
    md5: str = ""
    sha1: str = ""
    sha256: str = ""
    imphash: str = ""
    ssdeep: str = ""


@dataclass
class PeSection:
    name: str
    virtual_size: int
    raw_size: int
    entropy: float


@dataclass
class PeInfo:
    is_pe: bool = False
    machine: str = ""
    compile_time: str = ""
    subsystem: str = ""
    is_dll: bool = False
    imphash: str = ""
    sections: list[PeSection] = field(default_factory=list)
    imported_dlls: list[str] = field(default_factory=list)
    suspicious_imports: list[str] = field(default_factory=list)


@dataclass
class Indicators:
    ips: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)


@dataclass
class YaraMatch:
    rule: str
    tags: list[str] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass
class StaticResult:
    filename: str = ""
    size: int = 0
    filetype: str = ""
    hashes: Hashes = field(default_factory=Hashes)
    pe: PeInfo = field(default_factory=PeInfo)
    indicators: Indicators = field(default_factory=Indicators)
    yara: list[YaraMatch] = field(default_factory=list)
    interesting_strings: list[str] = field(default_factory=list)


@dataclass
class DynamicResult:
    engine: str = ""            # "tria.ge" | "CAPEv2"
    analyzed: bool = False
    score: float | None = None  # 0-10 en los dos sandbox
    sandbox_url: str = ""
    signatures: list[str] = field(default_factory=list)
    family: str = ""
    error: str = ""
    # Lo que el sandbox vio en la red durante la detonacion
    hosts: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    # Tecnicas ATT&CK que el propio sandbox asigna a sus firmas (CAPE)
    ttps: list[str] = field(default_factory=list)


@dataclass
class FamilyConfig:
    """Configuracion extraida de una familia conocida (C2, claves, campana...)."""
    family: str
    extractor: str              # "cobaltstrike" | "remcos" | "njrat" | "cape"
    c2: list[str] = field(default_factory=list)
    values: dict[str, Any] = field(default_factory=dict)
    confidence: str = "alta"    # alta: formato reconocido entero | media: heuristica
    source: str = "static"      # static | dynamic


@dataclass
class CtiMatch:
    """Un indicador de la muestra que ya esta en el feed de News CTI."""
    value: str                  # el valor del feed
    type: str                   # tipo en el feed (filehash-sha256, ipv4, domain, url...)
    matched: str                # lo que se busco (hash de la muestra, IP de sus strings...)
    threat: str = ""
    level: str = ""
    score: int | None = None
    sources: list[str] = field(default_factory=list)
    reference: str = ""
    first_seen: str = ""


@dataclass
class CtiCheck:
    checked: bool = False
    source: str = ""
    generated: str = ""
    indicators: int = 0
    matches: list[CtiMatch] = field(default_factory=list)
    error: str = ""


@dataclass
class AttackTechnique:
    id: str                     # p.ej. "T1547.001"
    name: str
    tactic: str = ""
    source: str = ""            # "static" | "dynamic"


@dataclass
class Report:
    tool: str = "malpipe"
    version: str = "1.1.0"
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    static: StaticResult = field(default_factory=StaticResult)
    dynamic: DynamicResult = field(default_factory=DynamicResult)
    attack: list[AttackTechnique] = field(default_factory=list)
    configs: list[FamilyConfig] = field(default_factory=list)
    cti: CtiCheck = field(default_factory=CtiCheck)
    verdict: str = "desconocido"   # limpio | sospechoso | malicioso | desconocido
    score: int = 0                 # 0-100 agregado
    reasons: list[str] = field(default_factory=list)   # por que esa puntuacion

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
