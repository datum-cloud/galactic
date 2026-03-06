Feature: Endpoint leaves established VPC
We emit route deletions for the endpoint to the remaining workers.

Scenario: First endpoint joins VPC
When a register event is received from "node1" for network "10.1.1.1/32" and endpoint "2001:1::1234:1234:1234:ffff"
Then 0 routes were published

Scenario: Second endpoint joins VPC
When a register event is received from "node2" for network "10.1.1.2/32" and endpoint "2001:2::1234:1234:1234:ffff"
Then 2 routes were published

Scenario: First endpoint leaves VPC
When a deregister event is received from "node1" for network "10.1.1.1/32" and endpoint "2001:1::1234:1234:1234:ffff"
Then 2 routes were published
And the routes are as follows:
| worker | network     | endpoint                    | segments                    | status |
| node1  | 10.1.1.2/32 | 2001:1::1234:1234:1234:ffff | 2001:2::1234:1234:1234:ffff | DELETE |
| node2  | 10.1.1.1/32 | 2001:2::1234:1234:1234:ffff | 2001:1::1234:1234:1234:ffff | DELETE |

Scenario: Second endpoint leaves VPC
When a deregister event is received from "node2" for network "10.1.1.2/32" and endpoint "2001:2::1234:1234:1234:ffff"
Then 0 routes were published
