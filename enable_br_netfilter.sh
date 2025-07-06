#!/bin/bash

# Controlla se il modulo br_netfilter è già caricato
if ! lsmod | grep -q br_netfilter; then
    echo "Caricando il modulo br_netfilter..."
    sudo modprobe br_netfilter
else
    echo "Il modulo br_netfilter è già caricato."
fi

# Abilita il filtraggio dei pacchetti bridged da iptables
echo "Abilitando net.bridge.bridge-nf-call-iptables=1..."
sudo sysctl -w net.bridge.bridge-nf-call-iptables=1

## Rendi permanente la configurazione modificando sysctl.conf
#if ! grep -q "net.bridge.bridge-nf-call-iptables=1" /etc/sysctl.conf; then
#    echo "net.bridge.bridge-nf-call-iptables=1" | sudo tee -a /etc/sysctl.conf
#    echo "Configurazione permanente aggiunta a /etc/sysctl.conf"
#else
#    echo "La configurazione è già presente in /etc/sysctl.conf"
#fi

# Ricarica la configurazione sysctl
echo "Ricaricando la configurazione sysctl..."
sudo sysctl -p

# Verifica che la configurazione sia stata applicata
echo "Verifica della configurazione:"
cat /proc/sys/net/bridge/bridge-nf-call-iptables

echo "Configurazione completata!"
