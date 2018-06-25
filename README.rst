zklaim
======

.. image:: https://travis-ci.com/kiliant/zklaim.svg?token=s4ESSVhWi2q4PNSopjzk&branch=master
    :target: https://travis-ci.com/kiliant/zklaim

Instructions
~~~~~~~~~~~~
#. clone this repo ;)
#. to pull in the submodules: ``git submodule update --init --recursive``
#. to update the submodules at any time: ``git submodule update --recursive --remote``


Run the Example
~~~~~~~~~~~~~~~
#. follow the steps above
#. create build directory: ``mkdir build; cd build``
#. ``cmake ..``
#. ``make -j 4`` (adapt to the number of parallel jobs you want to run at max)
#. run example at ``src/main``


Run the Tests
~~~~~~~~~~~~~
The (unit) tests are run automatically by travis, which will notify the authors if something fails (on master!).

To run tests locally, a custom target for this implementation has been implemented:

#. follow the build instructions above
#. ``make bttest``
#. an overview of the tests (if successful etc.) will be displayed

Google's (unit) testing framework is used as a backend.

TODO
