# d-hcp
This is a little DHCP script that doesn't attempt to intrude on anything. 

This does the ABSOLUTE bare minimum. This is done intentionally. 

d-hcp REQUIRES root privileges to bind to receive broadcast packets on port 67/68.

## Compilation instructions
`dmd -i d-hcp.d`
