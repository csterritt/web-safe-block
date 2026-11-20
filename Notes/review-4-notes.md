## Notes from the third review code implementation

Left alone on purpose:

- Per-username throttle: it would let anyone lock a user out.
- Capping the session reload by the limits: the limits are fixed in the code and serve is the only writer.
- The purger keeping its state alive after a router is dropped: it only matters in tests; it's documented on build_router.
- remove-user -h and quoting paths in hint messages.
- Test temp-dir cleanup and the 6-second sleep in a test.
