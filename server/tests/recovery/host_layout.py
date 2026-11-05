"""Fixed paths inside the two independently owned cold-recovery guests."""
import re

PROJECT = 'nethub'
ROLES = {'runtime', 'postgres', 'caddy', 'frps', 'backup'}
SERVICE_ROLES = {'postgres': 'postgres', 'migrate': 'runtime', 'nethub-web': 'runtime',
                 'nethub-authz': 'runtime', 'admin-bootstrap': 'runtime', 'backup': 'backup',
                 'caddy': 'caddy', 'frps': 'frps'}
RUNNING = {'postgres', 'backup', 'nethub-web', 'nethub-authz', 'frps', 'caddy'}
WRITERS = ('backup', 'nethub-web', 'nethub-authz', 'frps', 'caddy')
UNITS = ('nethub-gui-issuer.service', 'nethub-gui-issuer.timer',
         'nethub-http01-cleanup.service', 'nethub-http01-cleanup.timer')
SOURCE = '/srv/nethub-source'
HELPER = '/usr/local/libexec/nethub'
DEPLOYMENT = '/srv/nethub-deployment'
TRANSFER = '/root/nethub-recovery'
COMPOSE = ('docker', 'compose', '--project-name', PROJECT,
           '--file', DEPLOYMENT + '/docker-compose.yml',
           '--file', DEPLOYMENT + '/docker-compose.override.yml')
VOLUMES = {name: '/var/lib/docker/volumes/' + PROJECT + '_' + name + '/_data'
           for name in ('caddy-data', 'caddy-config', 'database-backups')}
STATE_ROOTS = (SOURCE, DEPLOYMENT, '/var/backups/nethub', '/etc/nethub',
               '/var/lib/nethub-gui-acme', '/srv/nethub-http01', '/var/lib/nethub-http01', HELPER,
               *('/etc/systemd/system/' + unit for unit in UNITS), *VOLUMES.values())


def valid_tags(tags):
    return (isinstance(tags, dict) and set(tags) == ROLES
            and all(isinstance(value, str) and re.fullmatch('[a-zA-Z0-9][a-zA-Z0-9_./:-]{0,255}', value)
                    for value in tags.values())
            and len(set(tags.values())) == len(ROLES))
