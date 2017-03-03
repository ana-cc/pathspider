Usage Overview
==============

You can run PATHspider from the command line. In order for the Observer to
work, you will need permissions to capture raw packets from the network
interface. This will require you to use ``sudo`` or equivalent in order to
run PATHspider.

.. code-block:: text

 # pathspider --help
 usage: pathspider [-h] [-s] [-i INTERFACE] [-w WORKERS] [--input INPUTFILE]
                   [--output OUTPUTFILE] [-v]
                   PLUGIN ...

 Pathspider will spider the paths.

 optional arguments:
   -h, --help            show this help message and exit
   -s, --standalone      run in standalone mode. this is the default mode (and
                         currently the only supported mode). in the future,
                         mplane will be supported as a mode of operation.
   -i INTERFACE, --interface INTERFACE
                         the interface to use for the observer
   -w WORKERS, --workers WORKERS
                         number of workers to use
   --input INPUTFILE     a file containing a list of remote hosts to test, with
                         any accompanying metadata expected by the pathspider
                         test. this file should be formatted as a comma-
                         seperated values file. Defaults to standard input.
   --output OUTPUTFILE   the file to output results data to. Defaults to
                         standard output.
   -v, --verbose         log debug-level output.

 Plugins:
   The following plugins are available for use:

     dscp                DiffServ Codepoints
     tfo                 TCP Fast Open
     ecn                 Explicit Congestion Notification
     dnsresolv           DNS resolution for hostnames to IPv4 and v6 addresses

 Spider safely!

Quickstart Example
------------------

You can run a small study using the ECN plugin and the included
``webinput.csv`` file to measure path transparency to ECN for a small selection
of web servers and save the results in ``results.txt``:

.. code-block:: shell

 pathspider -i eth0 ecn </usr/share/doc/pathspider/examples/webinput.csv >results.txt

.. note::

 If you've not installed PATHspider from apt, you will find the webinput.csv
 example script in the examples folder of the source distribution.

Data Formats
------------

PATHspider uses `newline delimited JSON <http://ndjson.org/>`_ (ndjson) for
both the output format when in standalone (the default) mode. The ndjson format
gives flexibility in the actual contents of the data as different tests may
require data to remain associated with jobs, for example the Alexa ranking of a
webserver, so that it can be present in the final output, or in some cases the
data may be used as part of the test, for example when running tests against
authoritative DNS servers and needing to know a domain for which the server
should be authoritative.

.. _defaultoutput:

Input Format
~~~~~~~~~~~~

At a minimum, each job should contain an IP address in a ``dip`` field.
Depending on the plugin in use, more details may be required. Refer to the
documentation for the specific plugin for more information.

Output Format
~~~~~~~~~~~~~

In flow record mode, PATHspider's output is in the form of two records per job
as JSON dictionaries. One record will be for the baseline (A) connection, and
one for the experimental (B) connection. These JSON records contain the
original job information, any information added by the connection functions and
any information added by the Observer.

The connection logic of all the plugins that ship with the PATHspider
distribution will set a ``config`` value, either 0 or 1 (with 0 being baseline,
1 being experimental) to distinguish flows. Due to the highly parallel nature
of PATHspider, the two flows for a particular job may not be output together
and may have other flows between them. Any analysis tools will need to take
this into consideration.

The plugins that ship with the PATHspider distribution will also have the
following values set in their output:

+------------+----------------------------------------------------------------+
| Key        | Description                                                    |
+============+================================================================+
| config     | 0 for baseline, 1 for experimental                             |
+------------+----------------------------------------------------------------+
| spdr_state | 0 = OK, 1 = TIMEOUT, 2 = FAILED, 3 = SKIPPED                   |
+------------+----------------------------------------------------------------+
| dip        | Layer 3 (IPv4/IPv6) source address                             |
+------------+----------------------------------------------------------------+
| sp         | Layer 4 (TCP/UDP) source port                                  |
+------------+----------------------------------------------------------------+
| dp         | Layer 4 (TCP/UDP) destination port                             |
+------------+----------------------------------------------------------------+
| pkt_fwd    | A count of the number of packets seen in the forward direction |
+------------+----------------------------------------------------------------+
| pkt_rev    | A count of the number of packets seen in the reverse direction |
+------------+----------------------------------------------------------------+
| oct_fwd    | A count of the number of octets seen in the forward direction  |
+------------+----------------------------------------------------------------+
| oct_rev    | A count of the number of octets seen in the reverse direction  |
+------------+----------------------------------------------------------------+

For detail on the values in individual plugins, see the section for that plugin
later in this documentation.

