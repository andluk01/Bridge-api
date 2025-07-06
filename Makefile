VENV_DIR=venv
PYTHON=$(VENV_DIR)/bin/python
PIP=$(VENV_DIR)/bin/pip
UVICORN=$(VENV_DIR)/bin/uvicorn

# Path per lo script di configurazione
ENABLE_BR_NETFILTER_SCRIPT=enable_br_netfilter.sh

.PHONY: help venv install freeze clean run

help:
	@echo "Comandi disponibili:"
	@echo "  make venv          - Crea un ambiente virtuale in $(VENV_DIR)"
	@echo "  make install       - Installa le dipendenze da requirements.txt"
	@echo "  make run           - Esegue lo script enable_br_netfilter.sh e poi main.py"

venv:
	python3 -m venv $(VENV_DIR)
	@echo "Per attivare l'ambiente virtuale: source $(VENV_DIR)/bin/activate"

install:
	$(PIP) install -r requirements.txt
run:
	# Esegui lo script enable_br_netfilter.sh prima di avviare main.py con uvicorn
	@echo "Eseguendo lo script enable_br_netfilter.sh..."
	@bash $(ENABLE_BR_NETFILTER_SCRIPT)
	$(UVICORN) main:app --host 0.0.0.0 --port 8000
