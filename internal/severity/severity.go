package severity

import "fmt"

var order = map[string]int{
	"low":      1,
	"medium":   2,
	"high":     3,
	"critical": 4,
}

func Normalize(level string) (string, error) {
	if _, ok := order[level]; !ok {
		return "", fmt.Errorf("invalid severity level: %s", level)
	}
	return level, nil
}

func MeetsOrAbove(level string, threshold string) bool {
	l, okL := order[level]
	t, okT := order[threshold]
	if !okL || !okT {
		return false
	}
	return l >= t
}

func Max(levels ...string) string {
	maxRank := 0
	maxLevel := ""
	for _, l := range levels {
		r := order[l]
		if r > maxRank {
			maxRank = r
			maxLevel = l
		}
	}
	return maxLevel
}
