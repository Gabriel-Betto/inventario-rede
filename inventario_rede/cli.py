"""Linha de comando: ``python -m inventario_rede ...``"""

from __future__ import annotations

import argparse
import ipaddress
import sys
from pathlib import Path
from typing import List, Optional

from . import __version__
from .analise import achar_conflitos, consolidar, ips_livres, parse_pool
from .parsers import (
    ORIGEM_ARP,
    ORIGEM_DHCP,
    ORIGEM_ESTATICO,
    ler_texto,
    parse_arp,
    parse_dhcp_leases,
    parse_estaticos,
)
from .relatorio import gerar_relatorios

EXEMPLO = """exemplo:
  python -m inventario_rede --arp data/arp_windows_exemplo.txt --dhcp data/dhcpd_leases_exemplo.txt \\
      --estaticos data/estaticos_exemplo.csv --rede 192.168.10.0/24 --pool 192.168.10.100-192.168.10.200
"""


def criar_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="inventario_rede",
        description="Monta o inventário de IPs da rede a partir de ARP, leases do DHCP e IPs estáticos.",
        epilog=EXEMPLO,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--arp", nargs="+", metavar="ARQ", help="saída(s) de 'arp -a' / 'arp -an' / 'ip neigh'")
    p.add_argument("--dhcp", metavar="ARQ", help="arquivo dhcpd.leases (formato ISC)")
    p.add_argument("--estaticos", metavar="CSV", help="CSV com colunas ip, mac, hostname, descricao")
    p.add_argument("--rede", metavar="CIDR", help="rede analisada, ex.: 192.168.10.0/24 (habilita IPs livres)")
    p.add_argument("--pool", metavar="INI-FIM", help="faixa do DHCP, ex.: 192.168.10.100-192.168.10.200")
    p.add_argument("--reservar", nargs="+", default=[], metavar="IP", help="IPs que não devem aparecer como livres")
    p.add_argument("--saida", default="saida", metavar="PASTA", help="pasta dos relatórios (padrão: saida)")
    p.add_argument("--sep", default=";", help="separador dos CSV (padrão ';', o do Excel em português)")
    p.add_argument("--xlsx", action="store_true", help="gera também um .xlsx (precisa de openpyxl)")
    p.add_argument(
        "--validar-expiracao",
        action="store_true",
        help="descarta leases do DHCP cuja data de expiração já passou (use com leases recentes)",
    )
    p.add_argument(
        "--falhar-se-conflito",
        action="store_true",
        help="termina com código 2 se houver conflito de gravidade ALTA (útil em automação)",
    )
    p.add_argument("--versao", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = criar_parser().parse_args(argv)

    if not (args.arp or args.dhcp or args.estaticos):
        print("Erro: informe pelo menos uma fonte (--arp, --dhcp ou --estaticos).", file=sys.stderr)
        return 1

    rede = None
    pool = None
    try:
        if args.rede:
            rede = ipaddress.ip_network(args.rede, strict=False)
            if rede.version != 4:
                raise ValueError("só IPv4 é suportado")
        if args.pool:
            pool = parse_pool(args.pool)
    except ValueError as erro:
        print(f"Erro nos parâmetros: {erro}", file=sys.stderr)
        return 1

    registros = []
    fontes = set()
    avisos: List[str] = []
    try:
        if args.arp:
            fontes.add(ORIGEM_ARP)
            for arquivo in args.arp:
                registros += parse_arp(ler_texto(arquivo))
        if args.dhcp:
            fontes.add(ORIGEM_DHCP)
            registros += parse_dhcp_leases(ler_texto(args.dhcp), validar_expiracao=args.validar_expiracao)
        if args.estaticos:
            fontes.add(ORIGEM_ESTATICO)
            estaticos, avisos = parse_estaticos(ler_texto(args.estaticos))
            registros += estaticos
    except OSError as erro:
        print(f"Erro ao ler arquivo: {erro}", file=sys.stderr)
        return 1

    dispositivos = consolidar(registros)
    conflitos = achar_conflitos(registros, fontes, pool)

    livres = None
    if rede is not None:
        try:
            livres = ips_livres(rede, [d.ip for d in dispositivos], args.reservar, pool)
        except ValueError as erro:
            print(f"Erro nos parâmetros: {erro}", file=sys.stderr)
            return 1

    try:
        arquivos = gerar_relatorios(
            Path(args.saida), dispositivos, conflitos, livres, rede=rede, separador=args.sep, xlsx=args.xlsx
        )
    except RuntimeError as erro:
        print(f"Erro: {erro}", file=sys.stderr)
        return 1

    for aviso in avisos:
        print(f"Aviso (estáticos): {aviso}", file=sys.stderr)

    por_tipo = {"Estático": 0, "DHCP": 0, "Só ARP": 0}
    for d in dispositivos:
        por_tipo[d.tipo] += 1
    altas = sum(1 for c in conflitos if c.gravidade == "ALTA")
    medias = sum(1 for c in conflitos if c.gravidade == "MÉDIA")
    infos = sum(1 for c in conflitos if c.gravidade == "INFO")

    print("Inventário de rede")
    print(
        f"  Dispositivos: {len(dispositivos)} "
        f"(estáticos {por_tipo['Estático']}, DHCP {por_tipo['DHCP']}, só ARP {por_tipo['Só ARP']})"
    )
    print(f"  Problemas: {len(conflitos)} (alta {altas}, média {medias}, info {infos})")
    for c in conflitos:
        print(f"    [{c.gravidade}] {c.tipo}: {c.alvo}")
    if livres is not None:
        fora = sum(1 for _, zona in livres if zona == "Fora do pool")
        print(f"  IPs livres em {rede}: {len(livres)} ({fora} fora do pool DHCP)")
    print("Arquivos gerados:")
    for arquivo in arquivos:
        print(f"  {arquivo}")

    if args.falhar_se_conflito and altas:
        return 2
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
