#!/bin/bash
# Entrypoint for the Tethealla Docker Application
#  starts each service in their own screen session.
#  Updated: 10/30/2021
#  Author: kotori <kotori83@gmail.com>

# starts a particular service by name.
start_service() {
    service_name="$1"
	echo "Starting: ${service_name} via screen"

	# Execute the server application via screen.
	screen -L -Logfile $service_name.log -dmS "$service_name" bash -c "cd /server; ./bin/$service_name"
	
	# Sleep for a few seconds to let the service to fully initialize.
	sleep 2
	svc_pid=$(pidof ${service_name})
	echo $svc_pid > $service_name.pid
	echo "$service_name started with pid: $svc_pid"
}

# Update IP first, this should only be run ONCE!
#  file: ip.updated is created after the first run.
if [ ! -f 'ip.updated' ]; then
    ./update-ip.sh
else
    echo "Starting preconfigured setup."
fi

# Ship Key Check
if [ ! -f 'shipkey.dat' ]; then
    # no shipkey, generate a new one.
    echo "shipkey.dat missing, generating a new shipkey..."
    ./bin/make_key
fi

# Accounts Check
if [ ! -f 'account.dat' ]; then
    # no accounts exist!
    echo "No Accounts exist, perhaps you should make one?"
    echo "Make An Account with: "
    echo "# docker-compose exec tethealla ./bin/account_add"
    exit 1
fi

# The 3 Tethealla services:
TETHEALLA_SVCS="patch_server login_server ship_server"

# Service startup loop
for svc in $TETHEALLA_SVCS; do
	# Start the service in the bin dir.
	start_service $svc
done

# Tail the various logs for 2 reasons:
#  1.) to keep the docker process alive.
#  2.) to be able to view the log output with `docker logs --f`
tail -f /server/*.log
