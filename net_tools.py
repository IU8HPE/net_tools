	#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Network Tools GUI 

Funzionalità:
- CIDR → IP Range (prima/ultima IP, network, broadcast, #host, netmask, wildcard)
- IP Range → CIDR (copertura minima con liste di CIDR)
- Aggregazione CIDR (merge/collapse di reti adiacenti/sovrapposte)
- Subnetter (spezza una rete in sottoreti di un nuovo prefisso)
- Supernetter (espandi una rete a un prefisso più piccolo se possibile)
- Utility IP (IP ↔ int, reverse DNS, formato binario)

Compatibilità IPv4/IPv6. Nessuna dipendenza esterna (usa solo libreria standard).
"""

import tkinter as tk
from tkinter import ttk, messagebox
import ipaddress
import socket

DARK_BG = "#0b1e3a"      # blu scurissimo
DARK_BG_2 = "#0f2a54"     # blu secondario
ACCENT = "#3aa0ff"       
TEXT = "#e6eefc"          # testo chiaro
MUTED = "#a9bddb"
ERROR = "#ff5c7a"

MONO = ("Cascadia Mono", 11)
SANS = ("Inter", 12)
SANS_B = ("Inter", 12, "bold")

# ----------------------------
# Utility IP
# ----------------------------

def parse_network(value: str) -> ipaddress._BaseNetwork:
    value = value.strip()
    return ipaddress.ip_network(value, strict=False)


def parse_address(value: str) -> ipaddress._BaseAddress:
    value = value.strip()
    return ipaddress.ip_address(value)


def cidr_to_range(cidr: str):
    net = parse_network(cidr)
    first = net.network_address
    last = net.broadcast_address if isinstance(net, ipaddress.IPv4Network) else list(net.hosts())[-1] if net.num_addresses > 1 else net.network_address
    # Per IPv6 non esiste "broadcast"; usiamo l'ultimo indirizzo della rete
    return net, first, last


def range_to_cidrs(start_ip: str, end_ip: str):
    start = parse_address(start_ip)
    end = parse_address(end_ip)
    if start.version != end.version:
        raise ValueError("Gli indirizzi devono essere della stessa famiglia (entrambi IPv4 o IPv6)")
    nets = ipaddress.summarize_address_range(start, end)
    return list(nets)


def aggregate_cidrs(cidrs: str):
    items = [c.strip() for c in cidrs.replace("\n", ",").split(",") if c.strip()]
    nets = [parse_network(x) for x in items]
    collapsed = list(ipaddress.collapse_addresses(nets))
    return collapsed


def subnetter(cidr: str, new_prefix: int):
    net = parse_network(cidr)
    if new_prefix < net.prefixlen:
        raise ValueError("Il nuovo prefisso deve essere >= del prefisso della rete di partenza")
    return list(net.subnets(new_prefix=new_prefix))


def supernetter(cidr: str, new_prefix: int):
    net = parse_network(cidr)
    if new_prefix > net.prefixlen:
        raise ValueError("Il nuovo prefisso deve essere <= del prefisso della rete di partenza")
    # supernet può fallire se new_prefix non è valido per il boundary
    while net.prefixlen > new_prefix:
        net = net.supernet()
    return net


def ip_to_int(value: str) -> int:
    addr = parse_address(value)
    return int(addr)


def int_to_ip(value: str):
    n = int(value)
    # Heuristica: prova IPv4 se rientra, altrimenti IPv6
    if 0 <= n <= (2**32 - 1):
        return ipaddress.IPv4Address(n)
    elif 0 <= n <= (2**128 - 1):
        return ipaddress.IPv6Address(n)
    else:
        raise ValueError("Intero fuori range per IPv4/IPv6")


def wildcard_mask(netmask: ipaddress._BaseAddress):
    if isinstance(netmask, ipaddress.IPv4Address):
        return ipaddress.IPv4Address(0xFFFFFFFF ^ int(netmask))
    # Wildcard mask non è tipica per IPv6; ritorniamo None
    return None


def bin_fmt(addr: ipaddress._BaseAddress) -> str:
    width = 32 if isinstance(addr, ipaddress.IPv4Address) else 128
    b = format(int(addr), f"0{width}b")
    if width == 32:
        return ".".join([b[i:i+8] for i in range(0, 32, 8)])
    else:
        # Gruppi da 16 bit per IPv6
        return ":".join([b[i:i+16] for i in range(0, 128, 16)])


def try_rdns(value: str):
    try:
        name, _, _ = socket.gethostbyaddr(str(parse_address(value)))
        return name
    except Exception:
        return "(nessun PTR)"

# ----------------------------
# GUI Helpers
# ----------------------------

class ThemedStyle(ttk.Style):
    def __init__(self, master=None):
        super().__init__(master)
        self.theme_use("clam")
        self.configure("TFrame", background=DARK_BG)
        self.configure("Card.TFrame", background=DARK_BG_2)
        self.configure("TNotebook", background=DARK_BG, foreground=TEXT)
        self.configure("TNotebook.Tab", background=DARK_BG_2, foreground=TEXT, padding=[12, 6])
        self.map("TNotebook.Tab", background=[("selected", ACCENT)], foreground=[("selected", DARK_BG)])
        self.configure("TLabel", background=DARK_BG_2, foreground=TEXT, font=SANS)
        self.configure("Muted.TLabel", background=DARK_BG_2, foreground=MUTED, font=("Inter", 11))
        self.configure("TButton", background=ACCENT, foreground=DARK_BG, font=SANS_B, padding=8)
        self.map("TButton", background=[("active", "#6bb9ff")])
        self.configure("TEntry", fieldbackground="#0c2247", foreground=TEXT, insertcolor=TEXT)
        self.configure("TSpinbox", fieldbackground="#0c2247", foreground=TEXT, insertcolor=TEXT)
        self.configure("TLabelframe", background=DARK_BG_2, foreground=TEXT)
        self.configure("TLabelframe.Label", background=DARK_BG_2, foreground=TEXT)
        self.configure("Treeview", background="#0c2247", fieldbackground="#0c2247", foreground=TEXT)
        self.configure("Treeview.Heading", background=DARK_BG_2, foreground=TEXT)


def make_card(parent):
    card = ttk.Frame(parent, style="Card.TFrame")
    card.pack(fill="x", padx=14, pady=12)
    return card


def labeled_entry(parent, text, default=""):
    frame = ttk.Frame(parent, style="Card.TFrame")
    frame.pack(fill="x", padx=0, pady=4)
    lbl = ttk.Label(frame, text=text)
    lbl.pack(side="left")
    var = tk.StringVar(value=default)
    ent = ttk.Entry(frame, textvariable=var)
    ent.pack(side="right", fill="x", expand=True)
    return var, ent


def show_error(msg: str):
    messagebox.showerror("Errore", msg)


# ----------------------------
# Tabs
# ----------------------------

class CIDRToRangeTab(ttk.Frame):
    def __init__(self, master):
        super().__init__(master, style="Card.TFrame")
        title = ttk.Label(self, text="CIDR → IP Range", font=("Inter", 16, "bold"))
        title.pack(anchor="w", padx=14, pady=(14, 8))

        card = make_card(self)
        self.cidr_var, self.cidr_entry = labeled_entry(card, "CIDR:", "192.168.1.0/24")
        btn = ttk.Button(card, text="Calcola", command=self.on_calc)
        btn.pack(anchor="e", pady=6)

        self.result = tk.Text(self, height=12, bg="#0c2247", fg=TEXT, bd=0, relief="flat", insertbackground=TEXT, font=MONO)
        self.result.pack(fill="both", expand=True, padx=14, pady=(2, 14))

    def on_calc(self):
        try:
            net, first, last = cidr_to_range(self.cidr_var.get())
            mask = net.netmask if isinstance(net, ipaddress.IPv4Network) else None
            wildcard = wildcard_mask(mask) if mask else None
            hosts = max(0, net.num_addresses - (2 if isinstance(net, ipaddress.IPv4Network) and net.prefixlen < 31 else 0))
            lines = []
            lines.append(f"Rete: {net.with_prefixlen}")
            if isinstance(net, ipaddress.IPv4Network):
                lines.append(f"Netmask: {mask} ({net.prefixlen})")
                if wildcard:
                    lines.append(f"Wildcard: {wildcard}")
                lines.append(f"Broadcast: {net.broadcast_address}")
            lines.append(f"Primo IP: {first}")
            lines.append(f"Ultimo IP: {last}")
            lines.append(f"# Indirizzi: {net.num_addresses}")
            lines.append(f"# Host utilizzabili: {hosts}")
            lines.append("")
            lines.append("Formati binari:")
            lines.append(f"  network  : {bin_fmt(net.network_address)}")
            if isinstance(net, ipaddress.IPv4Network):
                lines.append(f"  netmask  : {bin_fmt(net.netmask)}")
                lines.append(f"  broadcast: {bin_fmt(net.broadcast_address)}")
            lines.append(f"  first    : {bin_fmt(first)}")
            lines.append(f"  last     : {bin_fmt(last)}")

            self.result.delete("1.0", tk.END)
            self.result.insert("1.0", "\n".join(lines))
        except Exception as e:
            show_error(str(e))


class RangeToCIDRTab(ttk.Frame):
    def __init__(self, master):
        super().__init__(master, style="Card.TFrame")
        title = ttk.Label(self, text="IP Range → CIDR", font=("Inter", 16, "bold"))
        title.pack(anchor="w", padx=14, pady=(14, 8))

        card = make_card(self)
        self.start_var, _ = labeled_entry(card, "Start IP:", "192.168.1.10")
        self.end_var, _ = labeled_entry(card, "End IP:", "192.168.1.200")
        btn = ttk.Button(card, text="Calcola", command=self.on_calc)
        btn.pack(anchor="e", pady=6)

        self.result = tk.Text(self, height=12, bg="#0c2247", fg=TEXT, bd=0, relief="flat", insertbackground=TEXT, font=MONO)
        self.result.pack(fill="both", expand=True, padx=14, pady=(2, 14))

    def on_calc(self):
        try:
            nets = range_to_cidrs(self.start_var.get(), self.end_var.get())
            total = sum(n.num_addresses for n in nets)
            lines = [f"CIDR necessari ({len(nets)} blocchi, {total} indirizzi coperti):"]
            lines += [f"  - {n.with_prefixlen}" for n in nets]
            self.result.delete("1.0", tk.END)
            self.result.insert("1.0", "\n".join(lines))
        except Exception as e:
            show_error(str(e))


class AggregateCIDRTab(ttk.Frame):
    def __init__(self, master):
        super().__init__(master, style="Card.TFrame")
        title = ttk.Label(self, text="Aggregazione CIDR", font=("Inter", 16, "bold"))
        title.pack(anchor="w", padx=14, pady=(14, 8))

        card = make_card(self)
        lbl = ttk.Label(card, text="Inserisci reti (separate da virgole o nuove linee)")
        lbl.pack(anchor="w", pady=(0, 6))

        self.input = tk.Text(card, height=6, bg="#0c2247", fg=TEXT, bd=0, relief="flat", insertbackground=TEXT, font=MONO)
        self.input.pack(fill="x", padx=0, pady=(0, 6))
        self.input.insert("1.0", "10.0.0.0/24, 10.0.1.0/24\n10.0.2.0/23")

        btn = ttk.Button(card, text="Aggrega", command=self.on_calc)
        btn.pack(anchor="e", pady=4)

        self.result = tk.Text(self, height=10, bg="#0c2247", fg=TEXT, bd=0, relief="flat", insertbackground=TEXT, font=MONO)
        self.result.pack(fill="both", expand=True, padx=14, pady=(2, 14))

    def on_calc(self):
        try:
            collapsed = aggregate_cidrs(self.input.get("1.0", tk.END))
            lines = [f"Reti aggregate ({len(collapsed)} blocchi):"]
            lines += [f"  - {n.with_prefixlen}" for n in collapsed]
            self.result.delete("1.0", tk.END)
            self.result.insert("1.0", "\n".join(lines))
        except Exception as e:
            show_error(str(e))


class SubSuperTab(ttk.Frame):
    def __init__(self, master):
        super().__init__(master, style="Card.TFrame")
        title = ttk.Label(self, text="Subnetter & Supernetter", font=("Inter", 16, "bold"))
        title.pack(anchor="w", padx=14, pady=(14, 8))

        card = make_card(self)
        self.net_var, _ = labeled_entry(card, "Rete:", "10.0.0.0/16")

        row = ttk.Frame(card, style="Card.TFrame")
        row.pack(fill="x", pady=(6, 0))
        ttk.Label(row, text="Nuovo prefisso:").pack(side="left")
        self.prefix_var = tk.IntVar(value=24)
        self.prefix_spin = ttk.Spinbox(row, from_=0, to=128, textvariable=self.prefix_var, width=6)
        self.prefix_spin.pack(side="left", padx=(8, 0))

        btns = ttk.Frame(card, style="Card.TFrame")
        btns.pack(fill="x", pady=6)
        ttk.Button(btns, text="Subnetter", command=self.on_sub).pack(side="left")
        ttk.Button(btns, text="Supernetter", command=self.on_super).pack(side="left", padx=8)

        self.result = tk.Text(self, height=12, bg="#0c2247", fg=TEXT, bd=0, relief="flat", insertbackground=TEXT, font=MONO)
        self.result.pack(fill="both", expand=True, padx=14, pady=(2, 14))

    def on_sub(self):
        try:
            nets = subnetter(self.net_var.get(), int(self.prefix_var.get()))
            lines = [f"Sottoreti ({len(nets)}):"]
            preview = nets[:256]  # evita di stampare migliaia di righe
            lines += [f"  - {n.with_prefixlen}" for n in preview]
            if len(nets) > len(preview):
                lines.append(f"… e altre {len(nets)-len(preview)}")
            self.result.delete("1.0", tk.END)
            self.result.insert("1.0", "\n".join(lines))
        except Exception as e:
            show_error(str(e))

    def on_super(self):
        try:
            net = supernetter(self.net_var.get(), int(self.prefix_var.get()))
            self.result.delete("1.0", tk.END)
            self.result.insert("1.0", f"Supernet risultante: {net.with_prefixlen}")
        except Exception as e:
            show_error(str(e))


class IPUtilsTab(ttk.Frame):
    def __init__(self, master):
        super().__init__(master, style="Card.TFrame")
        title = ttk.Label(self, text="Utility IP", font=("Inter", 16, "bold"))
        title.pack(anchor="w", padx=14, pady=(14, 8))

        card = make_card(self)
        self.ip_var, _ = labeled_entry(card, "Indirizzo IP:", "8.8.8.8")
        self.int_var, _ = labeled_entry(card, "Intero:", "134744072")

        btns = ttk.Frame(card, style="Card.TFrame")
        btns.pack(fill="x", pady=6)
        ttk.Button(btns, text="IP → Int / Bin / PTR", command=self.do_ip).pack(side="left")
        ttk.Button(btns, text="Int → IP", command=self.do_int).pack(side="left", padx=8)

        self.result = tk.Text(self, height=12, bg="#0c2247", fg=TEXT, bd=0, relief="flat", insertbackground=TEXT, font=MONO)
        self.result.pack(fill="both", expand=True, padx=14, pady=(2, 14))

    def do_ip(self):
        try:
            addr = parse_address(self.ip_var.get())
            rdns = try_rdns(str(addr))
            lines = [
                f"IP      : {addr}",
                f"Versione: IPv{addr.version}",
                f"Integer : {int(addr)}",
                f"Binario : {bin_fmt(addr)}",
                f"PTR     : {rdns}",
            ]
            self.result.delete("1.0", tk.END)
            self.result.insert("1.0", "\n".join(lines))
        except Exception as e:
            show_error(str(e))

    def do_int(self):
        try:
            ip = int_to_ip(self.int_var.get())
            lines = [
                f"Intero : {self.int_var.get()}",
                f"IP     : {ip} (IPv{ip.version})",
                f"Binario: {bin_fmt(ip)}",
            ]
            self.result.delete("1.0", tk.END)
            self.result.insert("1.0", "\n".join(lines))
        except Exception as e:
            show_error(str(e))


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Network Tools")
        self.geometry("980x700")
        self.configure(bg=DARK_BG)
        ThemedStyle(self)

        header = ttk.Frame(self, style="TFrame")
        header.pack(fill="x")
        ttk.Label(header, text="Network Toolkit", foreground=TEXT, background=DARK_BG, font=("Inter", 20, "bold")).pack(side="left", padx=16, pady=12)
        ttk.Label(header, text="IPv4 & IPv6 • offline", style="Muted.TLabel").pack(side="right", padx=16)

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=10, pady=10)

        nb.add(CIDRToRangeTab(nb), text="CIDR → Range")
        nb.add(RangeToCIDRTab(nb), text="Range → CIDR")
        nb.add(AggregateCIDRTab(nb), text="Aggrega CIDR")
        nb.add(SubSuperTab(nb), text="Subnet/Supernet")
        nb.add(IPUtilsTab(nb), text="Utility IP")


# --- Robust avvio senza console (pyw): log su file + MessageBox in caso di errore
from pathlib import Path
import traceback, sys, os

LOG_PATH = Path(os.getenv('LOCALAPPDATA', Path.home())) / 'Temp' / 'network_tools_dark.log'

def _log_and_alert(ex: Exception):
    try:
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(LOG_PATH, 'a', encoding='utf-8') as f:
            f.write("\n=== EXCEPTION ===\n")
            traceback.print_exc(file=f)
    except Exception:
        pass
    # Mostra un MessageBox anche se tkinter non parte
    try:
        import ctypes
        msg = f"Errore all'avvio. Dettagli nel log:\n{LOG_PATH}"
        ctypes.windll.user32.MessageBoxW(0, msg, "Network Tools - Errore", 0x10)
    except Exception:
        pass

if __name__ == "__main__":
    try:
        App().mainloop()
    except Exception as ex:
        _log_and_alert(ex)
