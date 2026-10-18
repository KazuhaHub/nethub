<?php

function nethub_agent_services()
{
    return [[
        'description' => gettext('NetHub Agent tunnel'),
        'name' => 'nethub_agent_frpc',
        'pidfile' => '/var/run/nethub_agent_frpc.pid',
        'configd' => [
            'start' => ['nethub-agent start'],
            'stop' => ['nethub-agent stop'],
            'restart' => ['nethub-agent restart'],
        ],
    ]];
}

function nethub_agent_configure()
{
    // D21: automatic reconnect and periodic reconcile; no WAN-event restart.
    return [];
}
