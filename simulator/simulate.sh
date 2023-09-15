#!/bin/bash

# redis-cli -h keydb FLUSHALL || exit 1
python ecommerce.py || exit 1

# redis-cli -h keydb FLUSHALL || exit 1
python pci.py || exit 1

# redis-cli -h keydb FLUSHALL || exit 1
python password_manager.py || exit 1
