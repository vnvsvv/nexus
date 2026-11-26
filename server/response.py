"""Gateway response worker (process: nexus-response).

Roadmap: R8. The only process allowed to change the firewall.

- Endpoint commands (terminate_process) never come here: nexus-api queues them and
  the agents poll them, as in contracts/openapi.yaml.
- This worker takes gateway commands (block_connection, block_destination, unblock)
  in status queued from response_commands, re-validates them, runs nft, and writes a
  ResponseResult with executor="gateway".
- Validation is repeated here even though nexus-api checked first: closed action enum,
  typed params, IPs only inside the lab subnets, never a gateway or management IP,
  bounded timeout. Rejected commands get status "denied" with the reason.
- dry_run defaults to true. A dry-run command logs the exact nft argv and records
  status "dry_run" without executing.
- nft runs through subprocess with a fixed argument list, never a shell string, and
  only against the sets nexus_block_dst / nexus_block_src from lab/gateway/gateway-setup.sh.
- Wakes on NOTIFY plus a short poll; start-up processes any queued rows, so a crash
  loses nothing.
Runs as its own user with only CAP_NET_ADMIN (see systemd/nexus-response.service).
Not implemented yet.
"""
