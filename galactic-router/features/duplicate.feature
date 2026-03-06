Feature: First endpoint joins multiple times
We do not emit route additions to ourselves - EVER.

Scenario: First endpoint joins VPC
When a register event is received from "node1" for network "10.1.1.1/32" and endpoint "2001:1::1234:1234:1234:ffff"
Then 0 routes were published

Scenario: First endpoint joins VPC again
When a register event is received from "node1" for network "10.1.1.1/32" and endpoint "2001:1::1234:1234:1234:ffff"
Then 0 routes were published

Scenario: First endpoint joins VPC again again
When a register event is received from "node1" for network "10.1.1.1/32" and endpoint "2001:1::1234:1234:1234:ffff"
Then 0 routes were published
