# server.py
import asyncio, websockets, argparse, traceback, os, base64, hashlib, secrets, time, json as json
from pathlib import Path
from collections import defaultdict
from crypto_helpers import (
    generate_x25519_keypair,
    pubkey_to_b64,
    b64_to_pubkey,
    derive_aes_key,
    decrypt_message,
    encrypt_message,
    check_known_host,
    save_known_host,
)

# ---- Global State ----
clients = set()
client_info = {}               # ws -> {'name','aes_key','addr','auth','email'}
email_sessions = defaultdict(set)  # email -> set(ws)

USERS_PATH    = Path("users.json")
CONTACTS_PATH = Path("contacts.json")
GROUPS_PATH   = Path("groups.json")
HISTORY_DIR   = Path("history")
(HISTORY_DIR / "groups").mkdir(parents=True, exist_ok=True)



def _scrypt_hash(password: str, *, N=2**14, r=8, p=1) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=N, r=r, p=p, dklen=32)
    return f"scrypt${N}${r}${p}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"

def _scrypt_verify(password: str, digest: str) -> bool:
    try:
        scheme, N, r, p, salt_b64, dk_b64 = digest.split("$")
        assert scheme == "scrypt"
        N, r, p = int(N), int(r), int(p)
        salt = base64.b64decode(salt_b64)
        dk_expected = base64.b64decode(dk_b64)
        dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=N, r=r, p=p, dklen=len(dk_expected))
        return secrets.compare_digest(dk, dk_expected)
    except Exception:
        return False

def load_json(path: Path, default):
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    return default

def save_json_atomic(path: Path, data: dict):
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)

def load_users():    return load_json(USERS_PATH, {})
def save_users(u):   save_json_atomic(USERS_PATH, u)

def load_contacts(): return load_json(CONTACTS_PATH, {})  # {email: [emails]}
def save_contacts(d):save_json_atomic(CONTACTS_PATH, d)

def load_groups():   return load_json(GROUPS_PATH, {})    # {gid: {name, owner, members:[emails], created}}
def save_groups(g):  save_json_atomic(GROUPS_PATH, g)

def save_history(email: str, item: dict):
    HISTORY_DIR.mkdir(exist_ok=True)
    p = HISTORY_DIR / f"{email.replace('@','_at_')}.jsonl"
    with open(p, "a", encoding="utf-8") as f:
        f.write(json.dumps(item, ensure_ascii=False) + "\n")

def save_group_history(gid: str, item: dict):
    p = HISTORY_DIR / "groups" / f"{gid}.jsonl"
    with open(p, "a", encoding="utf-8") as f:
        f.write(json.dumps(item, ensure_ascii=False) + "\n")

def _valid_email(e: str) -> bool:
    return isinstance(e, str) and "@" in e and "." in e and 3 <= len(e) <= 254

async def handle_connection(ws):
    addr = ws.remote_address
    addr_str = (addr[0] + ':' + str(addr[1])) if addr else 'unknown'
    print(f'New connection from {addr_str}')
    our_priv, our_pub = generate_x25519_keypair()
    users     = load_users()
    contacts  = load_contacts()
    groups    = load_groups()

    try:
        # ---- Plain hello ----
        hello_raw = await ws.recv()
        if isinstance(hello_raw, bytes): raise ValueError("Expected plaintext JSON hello")
        hello = json.loads(hello_raw)
        client_name = hello.get('name', 'anon')
        client_pub_b64 = hello.get('x25519_pub') or ""
        if not client_pub_b64: raise ValueError("hello missing x25519_pub")
        client_pub = b64_to_pubkey(client_pub_b64)

        if not check_known_host(addr_str, client_pub_b64):
            print(f"[TOFU] Accepting and saving new client pubkey for {addr_str}")
            save_known_host(addr_str, client_pub_b64)
        else:
            print(f"Known client {addr_str} key verified")

        await ws.send(json.dumps({'type': 'hello', 'role': 'server', 'x25519_pub': pubkey_to_b64(our_pub)}))
        aes_key = derive_aes_key(our_priv, client_pub)
        print(f"Derived session key with {client_name} ({addr_str})")

        clients.add(ws)
        client_info[ws] = {'name': client_name, 'aes_key': aes_key, 'addr': addr_str, 'auth': False, 'email': None}

        # ---- Encrypted loop ----
        async for msg in ws:
            if not isinstance(msg, bytes):
                print('Received plaintext (unexpected), ignoring.')
                continue

            try:
                pt = decrypt_message(aes_key, msg)
                m = json.loads(pt.decode('utf8', errors='ignore'))
            except Exception as e:
                print('decrypt/parse error from', addr_str, e)
                continue

            t = m.get('type')

            # ---- Registrierung ----
            if t == 'register':
                email = (m.get('email') or '').strip().lower()
                password = m.get('password') or ''
                desired_name = (m.get('name') or '').strip() or email.split("@")[0]
                if not _valid_email(email):
                    await send(ws, aes_key, {'type':'register_err','reason':'invalid_email'}); continue
                if email in users:
                    await send(ws, aes_key, {'type':'register_err','reason':'email_exists'}); continue
                if len(password) < 8:
                    await send(ws, aes_key, {'type':'register_err','reason':'weak_password'}); continue
                users[email] = {"name": desired_name, "pw": _scrypt_hash(password)}
                save_users(users)
                await send(ws, aes_key, {'type':'register_ok','user':{'email':email,'name':desired_name}})
                # auto-login
                client_info[ws].update({'auth': True, 'email': email, 'name': desired_name})
                email_sessions[email].add(ws)
                await send(ws, aes_key, {'type':'auth_ok','user':{'email':email,'name':desired_name}})
                continue

            # Neue Typen: broadcast, voice, video_call, etc.
            if t == 'broadcast':
                recipients = m.get('to', [])
                body = m.get('body', '')
                for rcpt in recipients:
                    for rws in email_sessions.get(rcpt, []):
                        await send(rws, client_info[rws]['aes_key'], {
                            'type': 'broadcast', 'from': me_email, 'body': body
                        })
                await send(ws, aes_key, {'type':'broadcast_ok'})

            
            # ---- Login ----
            if t == 'auth':
                email = (m.get('email') or '').strip().lower()
                password = m.get('password') or ''
                u = users.get(email)
                if u and _scrypt_verify(password, u.get('pw','')):
                    client_info[ws]['auth'] = True
                    client_info[ws]['email'] = email
                    client_info[ws]['name']  = u.get('name') or client_name
                    email_sessions[email].add(ws)
                    await send(ws, aes_key, {'type':'auth_ok','user':{'email':email,'name':client_info[ws]['name']}})
                else:
                    await send(ws, aes_key, {'type':'auth_err','reason':'invalid_credentials'})
                continue

            # ---- Require auth for everything else ----
            if not client_info[ws].get('auth'):
                await send(ws, aes_key, {'type':'auth_required'}); continue

            me_email = client_info[ws]['email']
            me_name  = client_info[ws]['name']

            # ---- Public chat (kompatibel: 'text' = public) ----
            if t in ('public','text'):
                body = m.get('body','')
                if not body: continue
                await broadcast_public(f"{me_name}", body, exclude_ws=None)  # sende an alle
                save_history(me_email, {'ts': int(time.time()), 'type':'public', 'from': me_name, 'body': body})
                continue

            # ---- Kontakte ----
            if t == 'contacts_list':
                lst = contacts.get(me_email, [])
                # reiche Namen aus users nach
                items = [{'email':e, 'name': users.get(e,{}).get('name', e.split('@')[0])} for e in lst]
                await send(ws, aes_key, {'type':'contacts_list','items':items})
                continue

            if t == 'contacts_add':
                target = (m.get('email') or '').strip().lower()
                if not _valid_email(target) or target == me_email:
                    await send(ws, aes_key, {'type':'contacts_err','reason':'invalid_contact'}); continue
                if target not in users:
                    await send(ws, aes_key, {'type':'contacts_err','reason':'not_found'}); continue
                cur = contacts.get(me_email, [])
                if target not in cur:
                    cur.append(target)
                    contacts[me_email] = cur
                    save_contacts(contacts)
                await send(ws, aes_key, {'type':'contacts_ok','email':target})
                continue

            # ---- Direct Message (DM) ----
            if t == 'dm':
                to_email = (m.get('to') or '').strip().lower()
                body = m.get('body','')
                if not _valid_email(to_email) or not body:
                    await send(ws, aes_key, {'type':'dm_err','reason':'invalid'}); continue
                if to_email not in users:
                    await send(ws, aes_key, {'type':'dm_err','reason':'user_not_found'}); continue

                # an Empfänger senden (alle Sessions)
                recipients = list(email_sessions.get(to_email, []))
                for rws in recipients:
                    await send(rws, client_info[rws]['aes_key'], {'type':'dm','from': me_email,'name': me_name,'body': body})

                # optional OK an Sender
                await send(ws, aes_key, {'type':'dm_ok','to':to_email})
                # History (beide Seiten)
                ts = int(time.time())
                save_history(me_email, {'ts':ts,'type':'dm_out','to':to_email,'body':body})
                save_history(to_email, {'ts':ts,'type':'dm_in','from':me_email,'body':body})
                continue

            # ---- Gruppen ----
            if t == 'group_create':
                name = (m.get('name') or '').strip()
                if not name:
                    await send(ws, aes_key, {'type':'group_err','reason':'invalid_name'}); continue
                gid = secrets.token_hex(6)
                groups[gid] = {'name': name, 'owner': me_email, 'members':[me_email], 'created': int(time.time())}
                save_groups(groups)
                await send(ws, aes_key, {'type':'group_ok','action':'create','group':{'id':gid,'name':name}})
                continue

            if t == 'group_list':
                mine = [{'id':gid,'name':g['name'],'owner':g['owner']}
                        for gid,g in groups.items() if me_email in g.get('members',[])]
                await send(ws, aes_key, {'type':'group_list','items':mine})
                continue

            if t == 'group_add_member':
                gid = m.get('group_id'); newm = (m.get('email') or '').strip().lower()
                g = groups.get(gid)
                if not g or g.get('owner') != me_email:
                    await send(ws, aes_key, {'type':'group_err','reason':'no_permission'}); continue
                if newm not in users:
                    await send(ws, aes_key, {'type':'group_err','reason':'user_not_found'}); continue
                if newm not in g['members']:
                    g['members'].append(newm); save_groups(groups)
                await send(ws, aes_key, {'type':'group_ok','action':'add_member','group':{'id':gid,'name':g['name']},'email':newm})
                continue

            if t == 'group_msg':
                gid = m.get('group_id'); body = m.get('body','')
                g = groups.get(gid)
                if not g or me_email not in g.get('members',[]):
                    await send(ws, aes_key, {'type':'group_err','reason':'not_in_group'}); continue
                if not body: continue
                # an alle Mitglieder (online) außer Sender
                for member in g['members']:
                    if member == me_email: continue
                    for rws in email_sessions.get(member, []):
                        await send(rws, client_info[rws]['aes_key'], {
                            'type':'group_msg','group':{'id':gid,'name':g['name']},
                            'from': me_email, 'name': me_name, 'body': body
                        })
                save_group_history(gid, {'ts':int(time.time()),'from':me_email,'body':body})
                await send(ws, aes_key, {'type':'group_ok','action':'send','group':{'id':gid,'name':g['name']}})
                continue

            # Fallback
            await send(ws, aes_key, {'type':'error','reason':'unknown_type','got':t})

    except websockets.ConnectionClosed:
        pass
    except Exception as e:
        print('Error in connection handler:', e)
        traceback.print_exc()
    finally:
        info = client_info.pop(ws, None)
        clients.discard(ws)
        if info and info.get('email'):
            email_sessions[info['email']].discard(ws)

async def send(ws, aes_key, obj):
    data = json.dumps(obj).encode('utf8')
    await ws.send(encrypt_message(aes_key, data))

async def broadcast_public(sender_name: str, body: str, exclude_ws=None):
    payload = json.dumps({'type':'text','from': sender_name, 'body': body}).encode('utf8')
    for c in list(clients):
        if c == exclude_ws: continue
        info = client_info.get(c)
        if not info: continue
        try:
            await c.send(encrypt_message(info['aes_key'], payload))
        except Exception:
            pass

async def main(port):
    async with websockets.serve(handle_connection, '0.0.0.0', port, max_size=2**20):
        print(f'Server listening on port {port}')
        await asyncio.Future()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, required=True)
    args = parser.parse_args()
    try:
        asyncio.run(main(args.port))
    except KeyboardInterrupt:
        print('Server stopped')
