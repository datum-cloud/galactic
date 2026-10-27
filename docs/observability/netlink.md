# Netlink listings — `galactic_netlink_dump_*`

See [scraping and component ports](README.md#where-the-metrics-come-from).

The kernel interrupts a listing of links, addresses or routes when another
process changes them while it runs. The listing is then discarded and
retried: up to 5 rounds of 10 back-to-back attempts, with a pause of 20, 40,
60 and 80 ms between rounds. These counters show how often that happens on a
node, so sustained churn is visible before it makes a component fail.

| Metric                                    | Type    | Labels                              | Meaning                                                                                        |
| ----------------------------------------- | ------- | ----------------------------------- | ---------------------------------------------------------------------------------------------- |
| `galactic_netlink_dump_interrupted_total` | counter | `kind` (`link`, `address`, `route`) | Listing attempts the kernel interrupted. Each one is discarded and retried                     |
| `galactic_netlink_dump_failures_total`    | counter | `kind` (`link`, `address`, `route`) | Listings still interrupted on their last attempt. The caller got an error and acted on nothing |

Each process counts only its own listings, on its existing metrics port:

| Component                               | Port           | `job` from `config/monitoring/`          |
| --------------------------------------- | -------------- | ---------------------------------------- |
| `galactic-cni` (`credential-refresh`)   | 9180           | `galactic-cni`                           |
| `galactic-router`, `galactic-router-rr` | 9179           | `galactic-router` / `galactic-router-rr` |
| `galactic-nat`                          | 9182           | `galactic-nat`                           |
| `galactic-edge`                         | 9186           | `galactic-edge`                          |
| `galactic-vrf`                          | 9182 (default) | none shipped                             |
| `galactic-gateway`                      | 8081           | none shipped                             |

`galactic-vrf` and `galactic-gateway` need a scrape object of your own.
Until one exists, the queries below show nothing for them, which is not the
same as no churn.

The CNI plugins run once per attach and expose no metrics, so their
listings are not counted; an exhausted retry there fails the attach or
detach with the interruption error. Listings that do not go through the
shared retry are not counted either.

Interruptions are normal while pods start and stop. A failure is not: the
component returned an error for that pass and retries it later.

```promql
# Interruptions per second, by node, component and kind
sum by (node, job, kind) (rate(galactic_netlink_dump_interrupted_total[5m]))

# Listings that failed after every retry in the last hour
sum by (node, job, kind) (increase(galactic_netlink_dump_failures_total[1h])) > 0
```
