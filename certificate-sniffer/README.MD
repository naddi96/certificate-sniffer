# Istruzioni per eseguire il codice

## prerequisiti:
- Python3
- tshark

installati nella vostra macchina

## installare le dipendenze

attraverso il package manager pip

`pip install -r requirements.txt`

## avviare il sistema

`tshark.exe -i Ethernet -T ek  -Y tls.handshake.certificate | python main.py`

cambiare l'interfaccia "Ethernet" con l'iterfaccia di rete che si sta usando al momento 



