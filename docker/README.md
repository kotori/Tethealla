# Tethealla Dockerized

## Config
Adjust the following files with some defaults: 
- tethealla.ini
- ship.ini
You can raise XP rates, drop rates, etc.. Do not touch the REPLACE_ME_*** values.
These will be replaced on deployment by the entrypoint.sh script as needed.

## Build
```bash
docker-compose build tethealla
```

## Online services
```bash
docker-compose up -d tethealla
```

## Build and Online in one command
```bash
docker-compose up -d --build tethealla
```

## Offline services
The docker-compose stop command will stop your containers, but it won't remove them.
The docker-compose down command will stop your containers, but it also removes the stopped containers as well as any networks that were created.
You can take down 1 step further and add the -v flag to remove all volumes too.
```bash
docker-compose stop tethealla
```

## Monitor services
```bash
docker-compose logs --f tethealla
```

## Extras

### Add Accounts
```bash
docker-compose exec tethealla './bin/account_add' 
```

### View server statistics
```bash
docker stats
```

### Docker Consistent Networking
I added the following to my docker's /etc/docker/daemon.json file:
This ensures that my docker container's IP will always be in the 192.168.3.0 range.
This isn't necessary, but does keep things a little more consistent.
```json
{
  "default-address-pools" : [
    {
      "base" : "192.168.3.0/24",
      "size" : 24
    }
  ]
}
```
