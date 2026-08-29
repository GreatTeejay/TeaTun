package main

import "fmt"

func humanBytes(b float64) string {
	const unit = 1024.0
	if b < unit {
		return fmt.Sprintf("%.0fB", b)
	}
	units := []string{"KB", "MB", "GB", "TB", "PB"}
	v := b / unit
	i := 0
	for v >= unit && i < len(units)-1 {
		v /= unit
		i++
	}
	return fmt.Sprintf("%.2f%s", v, units[i])
}

// humanRate turns bits-per-second into a short human string.
func humanRate(bitsPerSec float64) string {
	if bitsPerSec < 0 {
		bitsPerSec = 0
	}
	const unit = 1000.0
	if bitsPerSec < unit {
		return fmt.Sprintf("%.0fbps", bitsPerSec)
	}
	units := []string{"Kbps", "Mbps", "Gbps", "Tbps"}
	v := bitsPerSec / unit
	i := 0
	for v >= unit && i < len(units)-1 {
		v /= unit
		i++
	}
	return fmt.Sprintf("%.2f%s", v, units[i])
}
