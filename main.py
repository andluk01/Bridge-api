from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, IPvAnyAddress
from typing import Literal
import json
import os
import subprocess
import configparser
import time
from apscheduler.schedulers.background import BackgroundScheduler

app = FastAPI()

LIMITED_IPS_FILE = "limited_ips.json"
CONFIG_FILE = "configurazione.conf"

# Carica limiti da file di configurazione
config = configparser.ConfigParser()
config.read(CONFIG_FILE)

LIMITS = {
    "sospetto": {
        "rate": config.get("iptables_limiti", "limite_sospetto"),
        "burst": config.get("iptables_limiti", "limite_sospetto_burst")
    },
    "malevolo": {
        "rate": config.get("iptables_limiti", "limite_malevolo"),
        "burst": config.get("iptables_limiti", "limite_malevolo_burst")
    }
}

TIME = {
    "sospetto": {
        "time_out": config.get("ip_time", "IP_TIMEOUT_SOSPETTO")
    },
    "malevolo": {
        "time_out": config.get("ip_time", "IP_TIMEOUT_MALEVOLO")
    }
}

# Inizializza file IP limitati
if not os.path.exists(LIMITED_IPS_FILE):
    with open(LIMITED_IPS_FILE, "w") as f:
        json.dump({}, f)

IP_TIMEOUT_SOSPETTO = float(TIME["sospetto"]["time_out"])
IP_TIMEOUT_MALEVOLO = float(TIME["malevolo"]["time_out"])

# Classe per la richiesta di limitazione
class QueueRequest(BaseModel):
    ip_class: IPvAnyAddress
    queue: Literal["buono", "sospetto", "malevolo"]

# Classe per la richiesta di rimozione dell'IP
class DeleteRequest(BaseModel):
    ip_class: IPvAnyAddress

# Schedulatore per rimuovere gli IP scaduti ogni 30 secondi
scheduler = BackgroundScheduler()

# Funzione per rimuovere gli IP scaduti periodicamente
def remove_expired_ips():
    print("Rimuovendo gli IP scaduti...")
    load_limited_ips()

# Impostazione del task schedulato per eseguire la rimozione ogni 30 secondi
scheduler.add_job(remove_expired_ips, 'interval', seconds=30)
scheduler.start()

# Carica IP limitati
def load_limited_ips():
    try:
        with open(LIMITED_IPS_FILE, "r") as f:
            data = json.load(f)
            # Rimuovi gli IP scaduti
            current_time = time.time()

            # Lista di IP da rimuovere con i rispettivi timeout
            to_remove = []

            for ip, entry in data.items():
                # Verifica se l'IP è sospetto o malevolo e applica il timeout corretto
                if isinstance(entry, dict) and isinstance(entry.get("timestamp"), (int, float)):
                    timestamp = float(entry["timestamp"])  # Convertiamo timestamp in float
                    if entry["queue"] == "sospetto" and current_time - timestamp > IP_TIMEOUT_SOSPETTO:
                        to_remove.append(ip)
                    elif entry["queue"] == "malevolo" and current_time - timestamp > IP_TIMEOUT_MALEVOLO:
                        to_remove.append(ip)

            # Rimuovi gli IP dalla lista 'data' e le regole iptables
            for ip in to_remove:
                remove_all_rules_for_ip(ip)
                
                if ip in data:
                    del data[ip]
                    print(f"IP {ip} rimosso con successo dalla coda.")

            # Salva i dati aggiornati nel file
            save_limited_ips(data)

            return data
    except Exception as e:
        print(f"Errore durante il caricamento degli IP limitati: {e}")
        raise HTTPException(status_code=500, detail="Errore durante il caricamento degli IP limitati")

# Funzione per salvare gli IP limitati nel file
def save_limited_ips(data):
    try:
        with open(LIMITED_IPS_FILE, "w") as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        print(f"Errore durante il salvataggio degli IP limitati: {e}")
        raise HTTPException(status_code=500, detail="Errore durante il salvataggio degli IP limitati")

# Funzione per rimuovere tutte le regole iptables per un IP
def remove_all_rules_for_ip(ip: str):
    try:
        result = subprocess.check_output(["iptables", "-L", "FORWARD", "-n", "--line-numbers"]).decode().splitlines()
        
        found = False
        for line in reversed(result):  # Iteriamo all'indietro per evitare problemi con il cambio degli indici
            if ip in line:
                parts = line.strip().split()
                if parts and parts[0].isdigit():
                    line_num = int(parts[0])
                    subprocess.run(["iptables", "-D", "FORWARD", str(line_num)], check=True)
                    found = True
        if not found:
            print(f"Nessuna regola trovata per l'IP {ip}.")
    except subprocess.CalledProcessError as e:
        print(f"Errore durante la pulizia delle regole per {ip}: {e}")
        raise HTTPException(status_code=500, detail=f"Errore durante la pulizia delle regole per {ip}")

# Funzione per applicare le regole di limitazione
def apply_limit_with_hashlimit(ip: str, rate: str, burst: str, label: str):
    try:
        # Rimuove eventuali regole precedenti
        remove_all_rules_for_ip(ip)
        
        # Regola con hashlimit per TCP
        subprocess.run([
            "iptables", "-A", "FORWARD", "-s", ip,
            "-p", "tcp",
            "-m", "hashlimit",
            "--hashlimit", f"{rate}/sec",
            "--hashlimit-burst", burst,
            "--hashlimit-mode", "srcip",
            "--hashlimit-name", label,
            "-j", "ACCEPT"
        ], check=True)

        # Regola di fallback DROP per TCP
        subprocess.run([
            "iptables", "-A", "FORWARD", "-s", ip,
            "-p", "tcp",
            "-j", "DROP"
        ], check=True)

    except subprocess.CalledProcessError as e:
        print(f"Errore applicazione regole per {ip}: {e}")
        raise HTTPException(status_code=500, detail=f"Errore applicazione regole per {ip}: {e}")

# Funzione per aggiungere un IP alla coda con timeout
def assign_to_queue_with_timeout(ip_str: str, queue: str):
    
    # Carica IP già limitati
    data = load_limited_ips()

    # Verifica se l'IP è già stato limitato
    if ip_str in data:
        current_queue = data[ip_str]["queue"]
        
        if current_queue == queue:
            # L'IP è già presente nella stessa lista
            raise HTTPException(status_code=400, detail="Indirizzo già limitato nella stessa lista")
        else:
            # Se l'IP è presente in un'altra lista (sospetto vs malevolo), rimuovilo dalla lista attuale
            print(f"L'IP {ip_str} è già presente nella lista {current_queue}. Rimuoviamo dalla lista precedente.")
            remove_all_rules_for_ip(ip_str)
            del data[ip_str]
    
    # Aggiungi l'IP alla nuova coda con timestamp
    data[ip_str] = {"queue": queue, "timestamp": time.time()}  # <-- Assicurati che timestamp sia un float
    save_limited_ips(data)

    
    # Applica la limitazione tramite hashlimit
    apply_limit_with_hashlimit(ip_str, LIMITS[queue]["rate"], LIMITS[queue]["burst"], f"{queue}_{ip_str.replace('.', '_')}")
    
    return {"status": "ok", "message": f"{ip_str} aggiunto alla coda '{queue}'"}

@app.post("/limit")
def assign_to_queue(req: QueueRequest):
    ip_str = str(req.ip_class)

    # Usa la funzione che include timeout
    return assign_to_queue_with_timeout(ip_str, req.queue)

@app.delete("/limit")
def remove_from_queue(req: DeleteRequest):
    data = load_limited_ips()
    ip_str = str(req.ip_class)

    if ip_str not in data:
        raise HTTPException(status_code=404, detail="Indirizzo non trovato")

    # Rimuovi le regole iptables associate all'IP
    remove_all_rules_for_ip(ip_str)

    # Rimuovi l'IP dalla coda nel file
    del data[ip_str]
    save_limited_ips(data)

    return {
        "status": "ok",
        "message": f"Limitazione rimossa per {ip_str}"
    }

@app.get("/limit")
def list_limited_ips():
    data = load_limited_ips()
    return {
        "status": "ok",
        "limited_ips": data
    }
