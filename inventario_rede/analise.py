"""Junta os registros e procura problemas: conflitos, IPs sem dono e IPs livres."""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .parsers import ORIGEM_ARP, ORIGEM_DHCP, ORIGEM_ESTATICO, Registro

ROTULO_ORIGEM = {ORIGEM_ARP: "ARP", ORIGEM_DHCP: "DHCP", ORIGEM_ESTATICO: "Estático"}
GRAVIDADES = {"ALTA": 0, "MÉDIA": 1, "INFO": 2}
MAX_PREFIXO_REDE = 16  # redes maiores que /16 gerariam listas gigantes de IPs livres


@dataclass
class Dispositivo:
    """Tudo o que se sabe sobre um IP, somando as fontes."""

    ip: str
    macs: Set[str] = field(default_factory=set)
    hostnames: Set[str] = field(default_factory=set)
    origens: Set[str] = field(default_factory=set)
    descricoes: Set[str] = field(default_factory=set)

    @property
    def tipo(self) -> str:
        if ORIGEM_ESTATICO in self.origens:
            return "Estático"
        if ORIGEM_DHCP in self.origens:
            return "DHCP"
        return "Só ARP"

    @property
    def fontes(self) -> str:
        ordem = [ORIGEM_ESTATICO, ORIGEM_DHCP, ORIGEM_ARP]
        return " + ".join(ROTULO_ORIGEM[o] for o in ordem if o in self.origens)


@dataclass(frozen=True)
class Conflito:
    gravidade: str  # ALTA, MÉDIA ou INFO
    tipo: str
    alvo: str
    detalhe: str


def _chave_ip(ip: str) -> int:
    return int(ipaddress.IPv4Address(ip))


def consolidar(registros: Iterable[Registro]) -> List[Dispositivo]:
    """Agrupa os registros por IP. Resultado ordenado pelo IP (numericamente)."""
    por_ip: Dict[str, Dispositivo] = {}
    for r in registros:
        disp = por_ip.setdefault(r.ip, Dispositivo(ip=r.ip))
        if r.mac:
            disp.macs.add(r.mac)
        if r.hostname:
            disp.hostnames.add(r.hostname)
        if r.descricao:
            disp.descricoes.add(r.descricao)
        disp.origens.add(r.origem)
    return sorted(por_ip.values(), key=lambda d: _chave_ip(d.ip))


def parse_pool(texto: str) -> Tuple[ipaddress.IPv4Address, ipaddress.IPv4Address]:
    """Lê ``192.168.10.100-192.168.10.200``. Levanta ``ValueError`` se estiver errado."""
    partes = texto.split("-")
    if len(partes) != 2:
        raise ValueError("pool deve ter o formato INICIO-FIM, ex.: 192.168.10.100-192.168.10.200")
    inicio, fim = (ipaddress.IPv4Address(p.strip()) for p in partes)
    if inicio > fim:
        raise ValueError("o início do pool deve ser menor ou igual ao fim")
    return inicio, fim


def ip_no_pool(ip: str, pool: Optional[Tuple[ipaddress.IPv4Address, ipaddress.IPv4Address]]) -> bool:
    if pool is None:
        return False
    return pool[0] <= ipaddress.IPv4Address(ip) <= pool[1]


def achar_conflitos(
    registros: Sequence[Registro],
    fontes_informadas: Set[str],
    pool: Optional[Tuple[ipaddress.IPv4Address, ipaddress.IPv4Address]] = None,
) -> List[Conflito]:
    """Procura problemas de endereçamento.

    ``fontes_informadas`` diz quais fontes o usuário realmente forneceu. Isso evita
    falsos alarmes: "dispositivo sem registro" só faz sentido se existe algo com que
    comparar (DHCP ou estáticos), e "estático sem atividade" só se há ARP ou DHCP.
    """
    achados: List[Conflito] = []

    macs_por_ip: Dict[str, Set[str]] = defaultdict(set)
    ips_por_mac: Dict[str, Set[str]] = defaultdict(set)
    fontes_por_ip_mac: Dict[Tuple[str, str], Set[str]] = defaultdict(set)
    linhas_estaticas_por_ip: Dict[str, int] = defaultdict(int)

    for r in registros:
        if r.mac:
            macs_por_ip[r.ip].add(r.mac)
            ips_por_mac[r.mac].add(r.ip)
            fontes_por_ip_mac[(r.ip, r.mac)].add(r.origem)
        if r.origem == ORIGEM_ESTATICO:
            linhas_estaticas_por_ip[r.ip] += 1

    # 1) O mesmo IP com MACs diferentes: o conflito clássico (dois equipamentos, um IP,
    #    ou o cadastro estático está desatualizado).
    for ip, macs in macs_por_ip.items():
        if len(macs) > 1:
            partes = []
            for mac in sorted(macs):
                origens = sorted(ROTULO_ORIGEM[o] for o in fontes_por_ip_mac[(ip, mac)])
                partes.append(f"{mac} ({', '.join(origens)})")
            achados.append(Conflito("ALTA", "IP com MACs diferentes", ip, "; ".join(partes)))

    # 2) IP estático cadastrado mais de uma vez.
    for ip, quantidade in linhas_estaticas_por_ip.items():
        if quantidade > 1:
            achados.append(
                Conflito("ALTA", "IP estático duplicado", ip, f"aparece {quantidade} vezes no CSV de estáticos")
            )

    # 3) IP estático dentro do pool do DHCP: o servidor pode entregar o mesmo IP a outro.
    if pool is not None:
        for ip in sorted(linhas_estaticas_por_ip, key=_chave_ip):
            if ip_no_pool(ip, pool):
                achados.append(
                    Conflito(
                        "MÉDIA",
                        "IP estático dentro do pool DHCP",
                        ip,
                        f"o pool vai de {pool[0]} a {pool[1]}; mova o IP para fora do pool ou reserve-o no DHCP",
                    )
                )

    # 4) Um MAC com mais de um IP: pode ser normal (cabo + Wi-Fi) ou um IP manual.
    for mac, ips in ips_por_mac.items():
        if len(ips) > 1:
            lista = ", ".join(sorted(ips, key=_chave_ip))
            achados.append(
                Conflito("MÉDIA", "MAC com mais de um IP", mac, f"IPs: {lista}. Verifique se é cabo + Wi-Fi ou um IP configurado à mão")
            )

    dispositivos = consolidar(registros)

    # 5) Está na rede (ARP) mas não está no DHCP nem no cadastro de estáticos.
    if fontes_informadas & {ORIGEM_DHCP, ORIGEM_ESTATICO}:
        for d in dispositivos:
            if d.origens == {ORIGEM_ARP}:
                achados.append(
                    Conflito(
                        "MÉDIA",
                        "Dispositivo sem registro",
                        d.ip,
                        f"visto no ARP ({', '.join(sorted(d.macs))}) mas ausente do DHCP e dos estáticos: IP manual ou equipamento desconhecido",
                    )
                )

    # 6) Cadastrado como estático, mas ninguém respondeu: desligado ou cadastro velho.
    if fontes_informadas & {ORIGEM_ARP, ORIGEM_DHCP}:
        for d in dispositivos:
            if d.origens == {ORIGEM_ESTATICO}:
                achados.append(
                    Conflito(
                        "INFO",
                        "Estático sem atividade",
                        d.ip,
                        "cadastrado, mas não apareceu no ARP nem no DHCP (equipamento desligado ou cadastro desatualizado). O ARP é só uma foto do momento",
                    )
                )

    achados.sort(key=lambda c: (GRAVIDADES[c.gravidade], c.tipo, c.alvo))
    return achados


def ips_livres(
    rede: ipaddress.IPv4Network,
    usados: Iterable[str],
    reservados: Iterable[str] = (),
    pool: Optional[Tuple[ipaddress.IPv4Address, ipaddress.IPv4Address]] = None,
) -> List[Tuple[str, str]]:
    """Lista os IPs livres da rede como ``(ip, zona)``.

    ``zona`` é "Pool DHCP" ou "Fora do pool" (os melhores candidatos para IP fixo).
    Endereço de rede e de broadcast nunca entram.
    """
    if rede.version != 4:
        raise ValueError("só IPv4 é suportado")
    if rede.prefixlen < MAX_PREFIXO_REDE:
        raise ValueError(f"rede grande demais: use /{MAX_PREFIXO_REDE} ou menor")

    ocupados = {ipaddress.IPv4Address(ip) for ip in usados} | {
        ipaddress.IPv4Address(ip) for ip in reservados
    }
    livres: List[Tuple[str, str]] = []
    for host in rede.hosts():
        if host in ocupados:
            continue
        zona = "Pool DHCP" if pool and pool[0] <= host <= pool[1] else "Fora do pool"
        livres.append((str(host), zona))
    return livres
