# gui_chat_client.py
import asyncio
import threading
import json
from dataclasses import dataclass
from typing import Optional

import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from ttkbootstrap.scrolled import ScrolledText
from tkinter import messagebox
import websockets

from crypto_helpers import (
    generate_x25519_keypair,
    pubkey_to_b64,
    b64_to_pubkey,
    derive_aes_key,
    encrypt_message,
    decrypt_message,
    check_known_host,
    save_known_host,
)

# --- Farben ---
CHARCOAL_BLACK = "#23241e"
ASH_IRON = "#4c4d4f"
GOLDEN_UMBER = "#c18d4b"
FOG_SILVER = "#a2a3a5"
MIST = "#e0e3e5"


@dataclass
class Identity:
    name: str
    email: str
    uri: str


class ChatApp:
    def __init__(self, root: ttk.Window):
        self.root = root
        self.root.title("Secure Chat Client")
        self.style = ttk.Style("cosmo")

        # Runtime-State
        self.loop: asyncio.AbstractEventLoop = asyncio.new_event_loop()
        self.ws: Optional[websockets.WebSocketClientProtocol] = None
        self.aes_key: Optional[bytes] = None
        self.identity: Optional[Identity] = None
        self._stop_event = threading.Event()
        self._connected = False

        # UI
        self.frame_login = None
        self.frame_chat = None
        self.contact_list = None
        self.chat_log: Optional[ScrolledText] = None
        self.msg_entry: Optional[ttk.Entry] = None
        self.theme_var = ttk.StringVar(value="cosmo")
        self.btn_send: Optional[ttk.Button] = None
        self.status_var = ttk.StringVar(value="Nicht verbunden")
        self.btn_connect: Optional[ttk.Button] = None

        # Neu: UI-Elemente für Kontakte
        self.contact_entry: Optional[ttk.Entry] = None
        self.btn_add_contact: Optional[ttk.Button] = None

        # Build UI
        self.build_login_ui()

        # Make sure we shutdown cleanly
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    # ---------- Login UI ----------
    def build_login_ui(self):
        self.frame_login = ttk.Frame(self.root, padding=24)
        self.frame_login.pack(fill=BOTH, expand=True)

        title = ttk.Label(self.frame_login, text="🔒 Secure Chat Login", font=("Helvetica", 16, "bold"),
                          foreground=GOLDEN_UMBER)
        title.pack(pady=(8, 18))

        grid = ttk.Frame(self.frame_login)
        grid.pack()

        ttk.Label(grid, text="E-Mail:").grid(row=0, column=0, sticky=W, padx=(0, 8), pady=6)
        self.email_entry = ttk.Entry(grid, width=32)
        self.email_entry.insert(0, "user@example.com")
        self.email_entry.grid(row=0, column=1, pady=6)

        ttk.Label(grid, text="Benutzername:").grid(row=1, column=0, sticky=W, padx=(0, 8), pady=6)
        self.username_entry = ttk.Entry(grid, width=32)
        self.username_entry.grid(row=1, column=1, pady=6)

        ttk.Label(grid, text="Server IP:").grid(row=2, column=0, sticky=W, padx=(0, 8), pady=6)
        self.ip_entry = ttk.Entry(grid, width=32)
        self.ip_entry.insert(0, "127.0.0.1")
        self.ip_entry.grid(row=2, column=1, pady=6)

        ttk.Label(grid, text="Port:").grid(row=3, column=0, sticky=W, padx=(0, 8), pady=6)
        self.port_entry = ttk.Entry(grid, width=32)
        self.port_entry.insert(0, "8765")
        self.port_entry.grid(row=3, column=1, pady=6)

        ttk.Label(grid, text="Design:").grid(row=4, column=0, sticky=W, padx=(0, 8), pady=6)
        self.theme_combo = ttk.Combobox(grid, values=self.style.theme_names(), textvariable=self.theme_var, width=30)
        self.theme_combo.grid(row=4, column=1, pady=6)

        self.btn_connect = ttk.Button(self.frame_login, text="Verbinden", bootstyle=SUCCESS, command=self.start_chat)
        self.btn_connect.pack(pady=14)

        status = ttk.Label(self.frame_login, textvariable=self.status_var, bootstyle=SECONDARY)
        status.pack()

    # ---------- Chat UI ----------
    def build_chat_ui(self):
        self.frame_login.pack_forget()
        self.style.theme_use(self.theme_var.get())

        self.frame_chat = ttk.Frame(self.root)
        self.frame_chat.pack(fill=BOTH, expand=True)

        # Left: Contacts
        left = ttk.Frame(self.frame_chat, width=200)
        left.pack(side=LEFT, fill=Y)
        left.configure(style="left.TFrame")

        ttk.Label(left, text="📇 Kontakte", font=("Helvetica", 10, "bold"), foreground=GOLDEN_UMBER).pack(pady=(6, 2))

       
        # --- Neues Kontakt-Formular ---
        frm = ttk.Frame(left)
        frm.pack(fill=X, padx=8, pady=6)

        ttk.Label(frm, text="Vorname:").pack(anchor="w")
        self.contact_first = ttk.Entry(frm)
        self.contact_first.pack(fill=X)

        ttk.Label(frm, text="Nachname:").pack(anchor="w")
        self.contact_last = ttk.Entry(frm)
        self.contact_last.pack(fill=X)

        ttk.Label(frm, text="E-Mail:").pack(anchor="w")
        self.contact_mail = ttk.Entry(frm)
        self.contact_mail.pack(fill=X)

        self.btn_add_contact = ttk.Button(frm, text="➕ Kontakt hinzufügen",
                                        bootstyle=SUCCESS, command=self.add_contact)
        self.btn_add_contact.pack(pady=4)


        self.contact_list = ttk.Treeview(left, show="tree")
        self.contact_list.pack(fill=BOTH, expand=True, padx=8, pady=(0, 8))
        self.contact_list.bind("<<TreeviewSelect>>", self.on_select_chat)

        # Öffentlicher Raum; echte Kontakte kommen vom Server
        self.contact_list.insert("", "end", iid="__public__", text="Allgemein (Gruppe)")
        self.contact_list.selection_set("__public__")

        # Right: Chat area
        right = ttk.Frame(self.frame_chat)
        right.pack(side=RIGHT, fill=BOTH, expand=True)

        self.chat_log = ScrolledText(right, autohide=True, padding=8)
        self.chat_log.pack(fill=BOTH, expand=True, padx=10, pady=10)
        self.chat_log.text.configure(state="disabled", wrap="word", bg=MIST, relief="flat")

        # --- Textformatierung: Styles definieren ---
        self.chat_log.text.tag_configure("bold", font=("Helvetica", 10, "bold"))
        self.chat_log.text.tag_configure("italic", font=("Helvetica", 10, "italic"))
        self.chat_log.text.tag_configure("strike", overstrike=True)
        self.chat_log.text.tag_configure("mono", font=("Courier", 10))

        entry_row = ttk.Frame(right)
        entry_row.pack(fill=X, padx=10, pady=(0, 10))

        self.msg_entry = ttk.Entry(entry_row)
        self.msg_entry.pack(side=LEFT, fill=X, expand=True)
        self.msg_entry.bind("<Return>", self.send_message)

        self.btn_send = ttk.Button(entry_row, text="Senden", bootstyle=INFO, command=self.send_message, state=DISABLED)
        self.btn_send.pack(side=LEFT, padx=(8, 0))

        # Status bar
        self.status_bar = ttk.Label(right, textvariable=self.status_var, bootstyle=SECONDARY)
        self.status_var.set("Verbunden…")
        self.status_bar.pack(anchor="e", padx=10)

        self.log_system(f"✅ Verbinden als {self.identity.name} ({self.identity.email})")

    # ---------- Connection Handling ----------
    def start_chat(self):
        name = self.username_entry.get().strip()
        email = self.email_entry.get().strip()
        ip = self.ip_entry.get().strip()
        port = self.port_entry.get().strip()

        if not (name and email and ip and port):
            messagebox.showerror("Fehler", "Bitte alle Felder ausfüllen.")
            return

        self.identity = Identity(name=name, email=email, uri=f"ws://{ip}:{port}")
        self.build_chat_ui()

        # Run asyncio client in background thread
        self._stop_event.clear()
        self.btn_connect and self.btn_connect.configure(state=DISABLED)
        threading.Thread(target=self._run_event_loop, daemon=True).start()

    def _run_event_loop(self):
        asyncio.set_event_loop(self.loop)
        try:
            self.loop.run_until_complete(self.connect_and_listen_with_retries())
        finally:
            # Ensure loop is closed when we stop
            try:
                self.loop.stop()
            except Exception:
                pass

    async def connect_and_listen_with_retries(self):
        backoff = 1
        max_backoff = 10
        while not self._stop_event.is_set():
            ok = await self.connect_and_listen()
            if ok:
                # clean disconnect
                break
            # failed -> retry with backoff
            self._set_status(f"Neuverbinden in {backoff}s …")
            await asyncio.sleep(backoff)
            backoff = min(max_backoff, backoff * 2)

    async def connect_and_listen(self) -> bool:
        try:
            our_priv, our_pub = generate_x25519_keypair()
            async with websockets.connect(self.identity.uri, max_size=2**20, ping_interval=20, ping_timeout=20) as ws:
                self.ws = ws
                # Hello senden
                await ws.send(json.dumps({
                    "type": "hello",
                    "role": "client",
                    "name": self.identity.name,
                    "email": self.identity.email,
                    "x25519_pub": pubkey_to_b64(our_pub),
                }))
                srv_hello_raw = await ws.recv()
                if isinstance(srv_hello_raw, bytes):
                    # Unexpected: server hello should be text
                    self.log_system("[Fehler] Unerwartete binäre Begrüßung vom Server")
                    return False
                try:
                    srv_hello = json.loads(srv_hello_raw)
                except Exception as e:
                    self.log_system(f"[Fehler] Ungültige Begrüßung vom Server: {e}")
                    return False

                srv_pub_b64 = srv_hello.get("x25519_pub")
                if not srv_pub_b64:
                    self.log_system("[Fehler] Server hat keinen Public Key gesendet")
                    return False
                srv_pub = b64_to_pubkey(srv_pub_b64)

                hostport = self.identity.uri.replace("ws://", "")
                if not check_known_host(hostport, srv_pub_b64):
                    # GUI: automatisch akzeptieren, aber klar anzeigen
                    self.log_system(f"[TOFU] Neuer Server-Key erkannt für {hostport} – akzeptiert und gespeichert.")
                    save_known_host(hostport, srv_pub_b64)

                self.aes_key = derive_aes_key(our_priv, srv_pub)
                self._connected = True
                self._set_status("Verbunden")
                self._set_send_enabled(True)
                self.log_system("[Sicher] Sitzung hergestellt.")

                # Neu: Kontakte beim Start laden (nach Auth auf Serverseite)
                self._send_json_encrypted({"type": "contacts_list"})

                async for msg in ws:
                    if isinstance(msg, bytes):
                        try:
                            pt = decrypt_message(self.aes_key, msg)
                            obj = json.loads(pt.decode("utf8"))

                            # --- Chat & Kontakt-Handling ---
                            t = obj.get("type")

                            if t == "text":
                                self.add_message(obj.get("from"), obj.get("body"))
                                continue

                            if t == "contacts_list":
                                items = obj.get("items", [])
                                self._populate_contacts(items)
                                self.log_system(f"[Kontakte] {len(items)} Einträge geladen.")
                                continue

                            if t == "contacts_ok":
                                email = obj.get("email")
                                self.log_system(f"[Kontakt] Hinzugefügt: {email}")
                                # Neu laden, um Namen aufzulösen
                                self._send_json_encrypted({"type": "contacts_list"})
                                continue

                            if t == "contacts_err":
                                reason = obj.get("reason", "unbekannt")
                                mapping = {
                                    "invalid_contact": "Ungültige E-Mail oder eigener Account.",
                                    "not_found": "Benutzer nicht gefunden.",
                                }
                                msg_text = mapping.get(reason, f"Fehler: {reason}")
                                self.log_system(f"[Kontakt] {msg_text}")
                                messagebox.showerror("Kontakt hinzufügen", msg_text)
                                continue

                            # Optional: weitere Info-Typen einfach loggen
                            self.log_system(f"[Info] {obj}")

                        except Exception as e:
                            self.log_system(f"[Fehler beim Entschlüsseln] {e}")
                    else:
                        # Optionale Info-Nachrichten
                        try:
                            obj = json.loads(msg)
                            if obj.get("type") == "info":
                                self.log_system(f"[Info] {obj.get('body')}")
                            else:
                                self.log_system(f"[Info] {msg}")
                        except Exception:
                            self.log_system(f"[Info] {msg}")
            # normal exit (user closed)
            return True
        except websockets.ConnectionClosedOK:
            # intentional close
            return True
        except Exception as e:
            self._connected = False
            self._set_send_enabled(False)
            self.log_system(f"[Verbindungsfehler] {e}")
            return False
        finally:
            self._connected = False
            self._set_send_enabled(False)
            self.ws = None

    # ---------- UI helpers ----------
    def on_select_chat(self, _evt=None):
        if not self.contact_list.selection():
            return
        sel = self.contact_list.item(self.contact_list.selection()[0], "text")
        self.log_system(f"📨 Chat gewechselt zu: {sel}")

    def _append_text(self, text: str, tag: Optional[str] = None):
        self.chat_log.text.configure(state="normal")
        if tag:
            self.chat_log.text.insert("end", text, (tag,))
        else:
            self.chat_log.text.insert("end", text)
        # simple bubble tag
        self.chat_log.text.tag_configure("bubble", background=MIST, lmargin1=6, lmargin2=6, rmargin=6)
        self.chat_log.text.tag_configure("you", foreground=GOLDEN_UMBER)
        self.chat_log.text.see("end")
        self.chat_log.text.configure(state="disabled")

    def add_message(self, sender: str, body: str):
        self._append_text(f"\n🗨️ {sender}: ", "you" if sender == "Du" else None)
        self._append_text(f"{body}\n", "bubble")

    def log_system(self, text: str):
        self._append_text(f"\n{text}\n")

    def _set_send_enabled(self, enabled: bool):
        if self.btn_send is not None:
            self.btn_send.configure(state=NORMAL if enabled else DISABLED)

    def _set_status(self, text: str):
        self.status_var.set(text)

    def send_message(self, _evt=None):
        msg = self.msg_entry.get().strip()
        if not msg:
            return
        if not (self.ws and self.aes_key and self._connected):
            messagebox.showwarning("Nicht verbunden", "Es besteht keine Verbindung zum Server.")
            return
        self.msg_entry.delete(0, "end")
        payload = json.dumps({"type": "text", "from": self.identity.name, "body": msg}).encode("utf8")
        data = encrypt_message(self.aes_key, payload)
        asyncio.run_coroutine_threadsafe(self.ws.send(data), self.loop)
        self.add_message("Du", msg)

    # ---------- NEU: Helfer fürs verschlüsselte Senden von JSON ----------
    def _send_json_encrypted(self, obj: dict):
        """JSON-Objekt verschlüsselt an den Server senden (Thread-safe)."""
        if not (self.ws and self.aes_key and self._connected):
            messagebox.showwarning("Nicht verbunden", "Es besteht keine Verbindung zum Server.")
            return
        data = json.dumps(obj).encode("utf8")
        asyncio.run_coroutine_threadsafe(self.ws.send(encrypt_message(self.aes_key, data)), self.loop)

    # ---------- NEU: Kontaktliste füllen ----------
    def _populate_contacts(self, items):
        # Alles außer dem öffentlichen Raum löschen
        for iid in list(self.contact_list.get_children()):
            if iid != "__public__":
                self.contact_list.delete(iid)
        # Neue Kontakte einsetzen
        for item in items:
            email = item.get('email') or ''
            name = item.get('name') or (email.split('@')[0] if email else 'Unbekannt')
            first = item.get("first", "")
            last  = item.get("last", "")
            email = item.get("email", "")
            label = f"{first} {last} <{email}>"
            self.contact_list.insert("", "end", text=label)

        # ---------- NEU: Kontakt hinzufügen ----------
    def add_contact(self):
        first = (self.contact_first.get() or "").strip()
        last  = (self.contact_last.get() or "").strip()
        email = (self.contact_mail.get() or "").strip().lower()

        if not (first and last and email):
            messagebox.showerror("Kontakt hinzufügen", "Bitte alle Felder ausfüllen.")
            return

        self._send_json_encrypted({
            "type": "contacts_add",
            "email": email,
            "first": first,
            "last": last
        })

        self.contact_first.delete(0, "end")
        self.contact_last.delete(0, "end")
        self.contact_mail.delete(0, "end")
    def on_close(self):
        # Hintergrund-Tasks stoppen
        self._stop_event.set()

        # Websocket sauber schließen
        if self.ws is not None:
            try:
                asyncio.run_coroutine_threadsafe(self.ws.close(), self.loop)
            except Exception:
                pass

        # GUI schließen
        try:
            self.root.after(150, self.root.destroy)
        except Exception:
            self.root.destroy()


if __name__ == "__main__":
    root = ttk.Window(themename="cosmo")
    root.configure(bg=FOG_SILVER)
    app = ChatApp(root)
    root.mainloop()
