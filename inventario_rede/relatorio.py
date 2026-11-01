"""Gravação dos resultados em CSV (e, opcionalmente, em um único arquivo Excel)."""

from __future__ import annotations

import csv
import ipaddress
from pathlib import Path
from typing import List, Optional, Sequence

from .analise import Conflito, Dispositivo

CAB_INVENTARIO = ["IP", "Tipo", "MAC", "Hostname", "Fontes", "Descrição", "Na rede informada"]
CAB_CONFLITOS = ["Gravidade", "Problema", "Alvo", "Detalhe"]
CAB_LIVRES = ["IP", "Zona"]


def linhas_inventario(
    dispositivos: Sequence[Dispositivo], rede: Optional[ipaddress.IPv4Network]
) -> List[List[str]]:
    linhas = []
    for d in dispositivos:
        if rede is None:
            na_rede = ""
        else:
            na_rede = "Sim" if ipaddress.IPv4Address(d.ip) in rede else "Não"
        linhas.append(
            [
                d.ip,
                d.tipo,
                " | ".join(sorted(d.macs)),
                " | ".join(sorted(d.hostnames)),
                d.fontes,
                " | ".join(sorted(d.descricoes)),
                na_rede,
            ]
        )
    return linhas


def linhas_conflitos(conflitos: Sequence[Conflito]) -> List[List[str]]:
    return [[c.gravidade, c.tipo, c.alvo, c.detalhe] for c in conflitos]


def _escrever_csv(caminho: Path, cabecalho: List[str], linhas: List[List[str]], sep: str) -> None:
    # utf-8-sig: o Excel abre com os acentos certos ao dar dois cliques.
    with open(caminho, "w", newline="", encoding="utf-8-sig") as arq:
        escritor = csv.writer(arq, delimiter=sep)
        escritor.writerow(cabecalho)
        escritor.writerows(linhas)


def _escrever_xlsx(caminho: Path, abas: List[tuple]) -> None:
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Font
        from openpyxl.utils import get_column_letter
    except ImportError as erro:  # pragma: no cover - depende do ambiente
        raise RuntimeError("para gerar .xlsx instale a dependência: pip install openpyxl") from erro

    livro = Workbook()
    livro.remove(livro.active)
    for titulo, cabecalho, linhas in abas:
        aba = livro.create_sheet(titulo)
        aba.append(cabecalho)
        for linha in linhas:
            aba.append(linha)
        for celula in aba[1]:
            celula.font = Font(bold=True)
        aba.freeze_panes = "A2"
        for coluna in range(1, len(cabecalho) + 1):
            maior = max(len(str(c.value or "")) for c in aba[get_column_letter(coluna)])
            aba.column_dimensions[get_column_letter(coluna)].width = min(maior + 2, 70)
    livro.save(caminho)


def gerar_relatorios(
    pasta: Path,
    dispositivos: Sequence[Dispositivo],
    conflitos: Sequence[Conflito],
    livres: Optional[Sequence[tuple]],
    rede: Optional[ipaddress.IPv4Network] = None,
    separador: str = ";",
    xlsx: bool = False,
) -> List[Path]:
    """Cria a pasta (se preciso) e grava os arquivos. Devolve os caminhos criados."""
    pasta.mkdir(parents=True, exist_ok=True)
    inventario = linhas_inventario(dispositivos, rede)
    problemas = linhas_conflitos(conflitos)
    criados: List[Path] = []

    destino = pasta / "inventario.csv"
    _escrever_csv(destino, CAB_INVENTARIO, inventario, separador)
    criados.append(destino)

    destino = pasta / "conflitos.csv"
    _escrever_csv(destino, CAB_CONFLITOS, problemas, separador)
    criados.append(destino)

    abas = [("Inventário", CAB_INVENTARIO, inventario), ("Conflitos", CAB_CONFLITOS, problemas)]
    if livres is not None:
        linhas_livres = [[ip, zona] for ip, zona in livres]
        destino = pasta / "ips_livres.csv"
        _escrever_csv(destino, CAB_LIVRES, linhas_livres, separador)
        criados.append(destino)
        abas.append(("IPs livres", CAB_LIVRES, linhas_livres))

    if xlsx:
        destino = pasta / "inventario_rede.xlsx"
        _escrever_xlsx(destino, abas)
        criados.append(destino)
    return criados
