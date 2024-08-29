# Parallax Server Overview

Multiple clients can access Parallax through the Parallax server. The current
implementation uses TCP/IP sockets with a custom wire protocol. Parallax server
starts with the following command:


```bash
./parallax_server -t <num of server threads> \
-b <IP address to bind to> \
-p <port to listen for new connections> \
-f <file to save Parallax data> \
-L0 <L0 size in MB> \
-GF <growth factor between LSM levels> \
-pf <optional: erase all data on startup>
``````

To use this feature, applications must use the public API of Parallax, with the
key difference being that they should link against parallax_client_lib
instead of parallax.

## Folder stucture

server folder contains all the server related code whereas par_net contain all
the client related code. The implementation the Parallax network library that
uses par_net classes is at <PARALLAX_HOME_FOLDER>/lib/api/parallax_client_lib.c
