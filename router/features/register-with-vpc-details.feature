Feature: Register with VPC details in SRv6 endpoints
Uses actual VPC identifiers including attachments to verify encoding/decoding.

Scenario: First endpoint joins VPC
When a register event is received from "node1" for network "10.1.1.2/32" and endpoint "2607:ed40:ff01:0:7197:93c7:5efd:66de"
And a register event is received from "node1" for network "2001:10:1:1::2/128" and endpoint "2607:ed40:ff01:0:7197:93c7:5efd:66de"
Then 0 routes were published

Scenario: Second endpoint joins VPC
When a register event is received from "node2" for network "10.1.1.3/32" and endpoint "2607:ed40:ff06:0:7197:93c7:5efd:5c99"
And a register event is received from "node2" for network "2001:10:1:1::3/128" and endpoint "2607:ed40:ff06:0:7197:93c7:5efd:5c99"
And a register event is received from "node2" for network "192.168.2.0/24" and endpoint "2607:ed40:ff06:0:7197:93c7:5efd:5c99"
And a register event is received from "node2" for network "2001:2::/64" and endpoint "2607:ed40:ff06:0:7197:93c7:5efd:5c99"
Then 6 routes were published
And the routes are as follows:
| worker | network            | endpoint                             | segments                             | status |
| node1  | 10.1.1.3/32        | 2607:ed40:ff01:0:7197:93c7:5efd:66de | 2607:ed40:ff06:0:7197:93c7:5efd:5c99 | ADD    |
| node1  | 2001:10:1:1::3/128 | 2607:ed40:ff01:0:7197:93c7:5efd:66de | 2607:ed40:ff06:0:7197:93c7:5efd:5c99 | ADD    |
| node1  | 192.168.2.0/24     | 2607:ed40:ff01:0:7197:93c7:5efd:66de | 2607:ed40:ff06:0:7197:93c7:5efd:5c99 | ADD    |
| node1  | 2001:2::/64        | 2607:ed40:ff01:0:7197:93c7:5efd:66de | 2607:ed40:ff06:0:7197:93c7:5efd:5c99 | ADD    |
| node2  | 10.1.1.2/32        | 2607:ed40:ff06:0:7197:93c7:5efd:5c99 | 2607:ed40:ff01:0:7197:93c7:5efd:66de | ADD    |
| node2  | 2001:10:1:1::2/128 | 2607:ed40:ff06:0:7197:93c7:5efd:5c99 | 2607:ed40:ff01:0:7197:93c7:5efd:66de | ADD    |
