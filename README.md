# Tethealla

Tethealla PSOBB server for linux.

## Installation

If you are opting for database usage, MySQL devel libraries are required along with your standard build toolset.
```bash
apt install default-libmysqlclient-dev cmake
```

Download the repo:
```bash
git clone https://github.com/kotori/Tethealla.git psobb_server
```

Build the server binaries:
```bash
cd psobb_server
mkdir -p build
cd build

# There are currently two cmake options.
# -DNO_SQL=OFF builds MySQL mode.
# -DNO_SQL=ON builds dat mode (DEFAULT).
# -DEXTRAS=ON builds 3 extra projects as seen below.
# -DEXTRAS=OFF does not build the extras (DEFAULT).

# For MySQL database mode.
cmake -DNO_SQL=OFF .. && make -j $(nproc)

# If you require the convert_quest, newtable, or convert_unitxt
cmake -DEXTRAS=ON .. && make -j $(nproc)

# Otherwise, if you accept the defaults:
cmake .. && make -j $(nproc)
```

The resulting binaries will be inside the 'build/deploy/bin/' directory.


## Usage

There are a number of "support" files needed to run the server itself.
> list of support files goes here


The way the server components rely on one another, they should be started in the following order:
- patch_server
- login_server
- ship_server

The binaries can be run from the deploy/bin directory (same directory as tethealla.ini) like so:
```bash
<deploy_dir>$ screen -S patch_server
<deploy_dir>$ ./bin/patch_server &
<deploy_dir>$ echo $! > patch.pid
Ctrl+A D
```

After starting each service, you may want to create an account or two to start with.
The account_add script will assist you in doing so. If you are using MySQL mode a database
table will be populated. If you are using DAT mode your accounts.dat file will be created/updated.
```bash
./bin/account_add
```

Here are some example startup scripts, I have systemd ones coming soon.


## Scripts

start-servers.sh
```bash
#!/bin/bash

TETH_DIR=/opt/gameservers/tethealla_server

cd ${TETH_DIR};

# Ensure the services are stopped, not needed with systemd.
/bin/bash ./stop-servers.sh

# The sleeps in between services simply gives things time to start.
#1.) Patch Server
./bin/patch_server &
echo $! > patch.pid
sleep 5
#2.) Login Server
./bin/login_server &
echo $! > login.pid
sleep 5
#3.) Ship Server
./bin/ship_server &
echo $! > ship.pid
```

stop-servers.sh
```bash
#!/bin/bash

TETH_DIR=/opt/gameservers/tethealla_server

cd ${TETH_DIR};

for i in $(cat *.pid); do kill -9 $i; done

rm -v *.pid

```



## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License
[GPL3](https://www.gnu.org/licenses/gpl-3.0.en.html)
