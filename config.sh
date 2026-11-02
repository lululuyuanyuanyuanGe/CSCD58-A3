#!/bin/bash

cd pox_module
python2 -m pip install --user -q -e .

pkill -9 sr_solution
pkill -9 sr

