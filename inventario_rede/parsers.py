"""Leitura das três fontes de dados.

- Tabela ARP (saída de ``arp -a`` no Windows, ``arp -an`` ou ``ip neigh`` no Linux)
- Leases do servidor DHCP no formato ISC (arquivo ``dhcpd.leases``, usado pelo pfSense)
- CSV com os IPs estáticos cadastrados (ip, mac, hostname, descricao)

Cada leitor devolve uma lista de ``Registro``. Nada aqui acessa a rede: tudo é texto.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

ORIGEM_ARP = "arp"
ORIGEM_DHCP = "dhcp"
ORIGEM_ESTATICO = "estatico"

# MAC com 6 pares hexadecimais separados por ":" ou "-"
_MAC_RE = re.compile(
    r"(?<![0-9A-Fa-f:-])([0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5})(?![0-9A-Fa-f:-])"
)
_IP_RE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")


@dataclass(frozen=True)
class Registro:
    """Uma observação de um dispositivo em uma das fontes."""

    ip: str
    mac: str  # em minúsculas, separado por ":"; pode ser "" se a fonte não informa
    origem: str
    hostname: str = ""
    descricao: str = ""


def normalizar_mac(texto: str) -> Optional[str]:
    """Devolve o MAC como ``aa:bb:cc:dd:ee:ff`` ou ``None`` se o texto não for um MAC."""
    encontrado = _MAC_RE.fullmatch(texto.strip())
    if not encontrado:
        return None
    return encontrado.group(1).lower().replace("-", ":")


def mac_de_dispositivo(mac: str) -> bool:
    """False para MACs que não identificam um equipamento (broadcast, multicast, zerado).

    Um MAC de equipamento tem o bit menos significativo do primeiro byte igual a 0.
    Isso já descarta ``ff:ff:ff:ff:ff:ff`` e os multicast como ``01:00:5e:...``.
    """
    if mac == "00:00:00:00:00:00":
        return False
    return int(mac.split(":")[0], 16) & 1 == 0


def ip_de_dispositivo(texto: str) -> bool:
    """True se o texto é um IPv4 que pode ser de um equipamento (não multicast/broadcast)."""
    try:
        ip = ipaddress.IPv4Address(texto)
    except ValueError:
        return False
    if ip.is_multicast or ip.is_unspecified or ip.is_loopback:
        return False
    return str(ip) != "255.255.255.255"


def parse_arp(texto: str) -> List[Registro]:
    """Lê a saída de ``arp -a`` (Windows), ``arp -an`` ou ``ip neigh`` (Linux).

    Por ser baseado em "achar um IP e um MAC na mesma linha", funciona nos três formatos.
    Linhas sem MAC (``<incomplete>``, ``FAILED``, cabeçalhos) são ignoradas.
    """
    vistos = set()
    registros: List[Registro] = []
    for linha in texto.splitlines():
        achou_mac = _MAC_RE.search(linha)
        achou_ip = _IP_RE.search(linha)
        if not achou_mac or not achou_ip:
            continue
        ip = achou_ip.group(1)
        mac = normalizar_mac(achou_mac.group(1))
        if not mac or not ip_de_dispositivo(ip) or not mac_de_dispositivo(mac):
            continue
        if (ip, mac) in vistos:
            continue
        vistos.add((ip, mac))
        registros.append(Registro(ip=ip, mac=mac, origem=ORIGEM_ARP))
    return registros


_LEASE_RE = re.compile(
    r"^lease\s+(\d{1,3}(?:\.\d{1,3}){3})\s*\{(.*?)^\}", re.DOTALL | re.MULTILINE
)
_ENDS_RE = re.compile(r"ends\s+(?:\d+\s+)?(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s*;")


def parse_dhcp_leases(
    texto: str,
    validar_expiracao: bool = False,
    agora: Optional[datetime] = None,
) -> List[Registro]:
    """Lê um arquivo ``dhcpd.leases`` (formato ISC).

    O arquivo só cresce: o mesmo IP pode aparecer várias vezes e vale o ÚLTIMO bloco.
    Só leases com ``binding state active`` entram. Com ``validar_expiracao=True``, leases
    cuja data ``ends`` (em UTC) já passou também são descartados.
    """
    ultimo_por_ip: Dict[str, str] = {}
    for achado in _LEASE_RE.finditer(texto):
        ultimo_por_ip[achado.group(1)] = achado.group(2)

    if agora is None:
        agora = datetime.now(timezone.utc).replace(tzinfo=None)

    registros: List[Registro] = []
    for ip, corpo in ultimo_por_ip.items():
        if "binding state active" not in corpo:
            continue
        mac_achado = re.search(r"hardware ethernet\s+([0-9A-Fa-f:]+)\s*;", corpo)
        mac = normalizar_mac(mac_achado.group(1)) if mac_achado else None
        if not mac or not ip_de_dispositivo(ip):
            continue
        if validar_expiracao:
            fim = _ENDS_RE.search(corpo)
            if fim and datetime.strptime(fim.group(1), "%Y/%m/%d %H:%M:%S") < agora:
                continue
        nome = re.search(r'client-hostname\s+"([^"]*)"\s*;', corpo)
        registros.append(
            Registro(
                ip=ip,
                mac=mac,
                origem=ORIGEM_DHCP,
                hostname=nome.group(1) if nome else "",
            )
        )
    return registros


_COLUNAS = {
    "ip": "ip",
    "mac": "mac",
    "hostname": "hostname",
    "nome": "hostname",
    "descricao": "descricao",
    "descrição": "descricao",
}


def parse_estaticos(texto: str) -> Tuple[List[Registro], List[str]]:
    """Lê o CSV de IPs estáticos. Devolve ``(registros, avisos)``.

    O separador (``;`` ou ``,``) é detectado pelo cabeçalho. Linhas com IP ou MAC
    inválido não entram e geram um aviso com o número da linha. O MAC pode ficar vazio.
    """
    texto = texto.lstrip("﻿")
    linhas = [l for l in texto.splitlines() if l.strip()]
    if not linhas:
        return [], []
    separador = ";" if ";" in linhas[0] else ","
    leitor = csv.reader(io.StringIO("\n".join(linhas)), delimiter=separador)

    cabecalho = [c.strip().lower() for c in next(leitor)]
    indice = {}
    for posicao, nome in enumerate(cabecalho):
        chave = _COLUNAS.get(nome)
        if chave and chave not in indice:
            indice[chave] = posicao
    if "ip" not in indice:
        return [], ["CSV de estáticos sem a coluna 'ip'"]

    def campo(valores: List[str], chave: str) -> str:
        pos = indice.get(chave)
        if pos is None or pos >= len(valores):
            return ""
        return valores[pos].strip()

    registros: List[Registro] = []
    avisos: List[str] = []
    for numero, valores in enumerate(leitor, start=2):
        ip = campo(valores, "ip")
        if not ip_de_dispositivo(ip):
            avisos.append(f"linha {numero}: IP inválido '{ip}'")
            continue
        bruto = campo(valores, "mac")
        mac = ""
        if bruto:
            mac = normalizar_mac(bruto) or ""
            if not mac:
                avisos.append(f"linha {numero}: MAC inválido '{bruto}' (linha ignorada)")
                continue
        registros.append(
            Registro(
                ip=ip,
                mac=mac,
                origem=ORIGEM_ESTATICO,
                hostname=campo(valores, "hostname"),
                descricao=campo(valores, "descricao"),
            )
        )
    return registros, avisos


def ler_texto(caminho) -> str:
    """Lê um arquivo de texto tentando as codificações comuns.

    No Windows PowerShell 5.1, ``arp -a > arq.txt`` grava em UTF-16 (com BOM); isso
    também é tratado aqui, além de UTF-8 (com ou sem BOM) e cp1252.
    """
    dados = Path(caminho).read_bytes()
    if dados.startswith((b"\xff\xfe", b"\xfe\xff")):
        return dados.decode("utf-16")
    if dados.startswith(b"\xef\xbb\xbf"):
        return dados.decode("utf-8-sig")
    try:
        return dados.decode("utf-8")
    except UnicodeDecodeError:
        return dados.decode("cp1252", errors="replace")
