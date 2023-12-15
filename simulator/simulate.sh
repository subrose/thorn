#!/bin/bash

python ecommerce.py || exit 1
python pci.py || exit 1
python password_manager.py || exit 1
python ops.py || exit 1
python bank.py || exit 1
