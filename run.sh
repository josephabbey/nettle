#!/bin/bash

sudo firewall-cmd --add-service=dhcp --permanent
sudo firewall-cmd --add-service=dns --permanent
sudo firewall-cmd --reload

sudo go run .
