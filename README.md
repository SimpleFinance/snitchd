# snitchd
`snitchd` is a loadable kernel module (LKM) for Linux. It periodically scans all of physical memory looking for various types of sensitive data:
 - Credit card numbers (PANs) -- based on a simple regex and a [Luhn checksum](https://en.wikipedia.org/wiki/Luhn_algorithm) validation.
 - Social Security numbers -- based on a simple regex and a few validations.
 - First and last names -- based on a list of common US names taken from US census data.
 - Email addresses -- based on a simple regex.
 - Routing numbers -- based on a list of valid numbers from the Federal Reserve. The routing portion of these numbers isn't sensitive by itself, but these are often paired with a full bank account number.

When it finds data that looks like one of these types, `snitchd` counts it and reports via [Graphite](https://graphite.readthedocs.org/en/latest/). This data can be used by other tools to detect when data is on a system where it doesn't belong.

Because the data type detection is heuristic, it's likely to detect several false positives on most systems. Detection and alerting logic based on the `snitchd` metrics should take this into account and do some basic filtering.

### Caveats
This code is not necessarily production ready. It is highly privileged code written in an unsafe language and exposed to a large amount of attacker-controlled input. Use with caution.

### Threat Model
`snitchd` is not meant to detect malicious copies of data. It is meant to help detect accidental leakage of data onto systems which are not meant to handle that type of data.

### Example Use Cases
These are some examples of security policies that could be enforced with the help of `snitchd`:

 - A development/test cluster of machines should not store or process any sensitive customer data.

 - Sensitive customer data should be encrypted at the application level before being stored in a database, so the database host should not contain any sensitive data.

 - Data sent through a load balancer should be encrypted end-to-end between the client and the upstream server, so buffered data on the load balancer host should not contain any sensitive data.

### Building
`snitchd` is built using [Ragel](https://www.colm.net/open-source/ragel/), a tool for writing efficient and safe pattern matching code using state machines. On Ubuntu 14.04, you can get all the dependencies using `sudo apt-get install build-essential ragel`. The code should then be buildable with `make`.

### Usage
`snitchd` depends on the `keyutils` package which provides helpers for resolving DNS names from kernel modules (`sudo apt-get install keyutils`).

It can then be loaded using `insmod`:

 ```
 sudo insmod snitchd-3.13.0-54-generic.ko interval=900 graphite_host=127.0.0.1 graphite_port=8125 graphite_prefix=snitchd.myhost
 ```

 - `interval`: how often to scan in seconds (default: 15 minutes)
 - `graphite_host`: [Graphite](https://graphite.readthedocs.org/en/latest/) hostname or IP (default: 127.0.0.1)
 - `graphite_port`: TCP port for Graphite (default: 2003).
 - `graphite_prefix`: prefix for values sent to Graphite (required)
 - `pan_prefix`: count possible PANs only if they begin with this value (default: no filter)

### Output Format
Output is in Graphite format, prefixed with the `graphite_prefix`:
```
snitchd.myhost.pans <number PAN-like values> <timestamp>
snitchd.myhost.ssns <number of SSN-like values> <timestamp>
snitchd.myhost.routing_numbers <number of routing number-like values> <timestamp>
snitchd.myhost.names <number of common names> <timestamp>
snitchd.myhost.emails <number of email-like values> <timestamp>
```

### Notice
Census data is public domain / [CC0 1.0](https://creativecommons.org/publicdomain/zero/1.0/) from https://deron.meranda.us/data/.

We can't distribute the Federal Reserve ACH routing number database (`FedACHdir.txt`), but the included `Makefile` should prompt you to download it.
