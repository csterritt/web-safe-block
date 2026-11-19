## Notes from the third review code implementation

Left alone on purpose:

- The monitor's 100 ms wait after each write: this is the deliberate check for a client that has disconnected. The lost-event cases I raised only affect events already sent to a dying connection, so I overstated that finding.
- Minor items: making the connection-info extractor optional, timestamps in log lines, OPTIONS * requests, and the full-table scans in session eviction.
