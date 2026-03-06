Feature: One endpoint deregisters multiple networks
We emit route additions for the relevant endpoints to the workers without sending duplicates.

Scenario: First endpoint joins VPC
When a register event is received from "node1" for network "10.1.1.1/32" and endpoint "2001:1::1234:1234:1234:ffff"
And a register event is received from "node1" for network "2001:10:1:1::1/32" and endpoint "2001:1::1234:1234:1234:ffff"
Then 0 routes were published

Scenario: Second endpoint joins VPC
When a register event is received from "node2" for network "10.1.1.2/32" and endpoint "2001:2::1234:1234:1234:ffff"
Then 3 routes were published

Scenario: First endpoint leaves VPC with first attachment
When a deregister event is received from "node1" for network "10.1.1.1/32" and endpoint "2001:1::1234:1234:1234:ffff"
Then 1 route was published
And the route is as follows:
| worker | network           | endpoint                    | segments                    | status |
| node2  | 10.1.1.1/32       | 2001:2::1234:1234:1234:ffff | 2001:1::1234:1234:1234:ffff | DELETE |

Scenario: First endpoint leaves VPC with second attachment
When a deregister event is received from "node1" for network "2001:10:1:1::1/32" and endpoint "2001:1::1234:1234:1234:ffff"
Then 2 routes were published
And the routes are as follows:
| worker | network           | endpoint                    | segments                    | status |
| node1  | 10.1.1.2/32       | 2001:1::1234:1234:1234:ffff | 2001:2::1234:1234:1234:ffff | DELETE |
| node2  | 2001:10:1:1::1/32 | 2001:2::1234:1234:1234:ffff | 2001:1::1234:1234:1234:ffff | DELETE |
