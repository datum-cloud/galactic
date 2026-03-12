package identifier

import (
	"fmt"
	"math/rand"
	"time"
)

const MaxVPC uint64 = 0xFFFFFFFFFFFF
const MaxVPCAttachment uint64 = 0xFFFF

type Identifier struct {
	r *rand.Rand
}

func New() *Identifier {
	return &Identifier{
		r: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func NewFromSeed(seed int64) *Identifier {
	return &Identifier{
		r: rand.New(rand.NewSource(seed)),
	}
}

func (id *Identifier) FromValue(value uint64, max uint64) (string, error) {
	if value == 0 || value == max {
		return "", fmt.Errorf("%d is a special value that cannot be used", value)
	}
	if value > max {
		return "", fmt.Errorf("%d exceeds maximum value %d", value, max)
	}
	maxLen := len(fmt.Sprintf("%x", max))
	return fmt.Sprintf("%0*x", maxLen, value), nil
}

func (id *Identifier) FromRandom(max uint64) (string, error) {
	n := uint64(id.r.Int63n(int64(max-1)) + int64(1))
	return id.FromValue(n, max)
}

func (id *Identifier) ForVPC() (string, error) {
	return id.FromRandom(MaxVPC)
}

func (id *Identifier) ForVPCAttachment() (string, error) {
	return id.FromRandom(MaxVPCAttachment)
}
