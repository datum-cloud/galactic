/*
Copyright © 2026 Datum Technology, Inc. All rights reserved.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

package leaderelection

import (
	"net"
	"time"

	"k8s.io/client-go/rest"
)

const (
	QPS   = 5
	Burst = 10
)

func RestConfig(base *rest.Config) *rest.Config {
	cfg := rest.CopyConfig(base)
	cfg.RateLimiter = nil
	cfg.QPS = QPS
	cfg.Burst = Burst
	cfg.Dial = (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}).DialContext
	return cfg
}
