# zklaim

[![Build Status](https://travis-ci.org/kiliant/zklaim.svg?branch=master)](https://travis-ci.org/kiliant/zklaim)

## Instructions
1. install dependencies
    - on Ubuntu 18.04: ``sudo apt-get install build-essential cmake git libgmp3-dev libprocps-dev python-markdown libboost-all-dev libssl-dev libgcrypt-dev``
2. clone this repo ;)
3. to pull in the submodules: ``git submodule update --init --recursive``
4. to update the submodules at any time: ``git submodule update --recursive --remote``


## Run the Example
1. follow the steps above
2. create build directory: ``mkdir build; cd build``
3. ``cmake ..``
4. ``make -j 4`` (adapt to the number of parallel jobs you want to run at max)
5. run example at ``src/main``


## Run the Tests
The (unit) tests are run automatically by travis, which will notify the authors if something fails (on master!).

To run tests locally, a custom target for this implementation has been implemented:

1. follow the build instructions above
2. ``make bttest``
3. an overview of the tests (if successful etc.) will be displayed

Google's (unit) testing framework is used as a backend.

TODO
