//go:build ignore

// mkicon renders the application icon (teal rounded square with a check mark
// and a signal dot) into a 256×256 PNG. Run: go run ./tools/mkicon winres/icon.png
package main

import (
	"image"
	"image/color"
	"image/png"
	"math"
	"os"
)

const size = 256

func main() {
	out := "winres/icon.png"
	if len(os.Args) > 1 {
		out = os.Args[1]
	}
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	const ss = 4 // supersampling
	bg := color.NRGBA{0x21, 0xa8, 0x9b, 0xff}
	bg2 := color.NRGBA{0x1a, 0x8c, 0x82, 0xff}
	white := color.NRGBA{0xff, 0xff, 0xff, 0xff}
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			var r, g, b, a float64
			for sy := 0; sy < ss; sy++ {
				for sx := 0; sx < ss; sx++ {
					px := float64(x) + (float64(sx)+0.5)/ss
					py := float64(y) + (float64(sy)+0.5)/ss
					c := sample(px, py, bg, bg2, white)
					r += float64(c.R) * float64(c.A) / 255
					g += float64(c.G) * float64(c.A) / 255
					b += float64(c.B) * float64(c.A) / 255
					a += float64(c.A)
				}
			}
			n := float64(ss * ss)
			if a > 0 {
				img.SetNRGBA(x, y, color.NRGBA{uint8(r / a * 255), uint8(g / a * 255), uint8(b / a * 255), uint8(a / n)})
			}
		}
	}
	f, err := os.Create(out)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	if err := png.Encode(f, img); err != nil {
		panic(err)
	}
}

// sample returns the colour at a sub-pixel position.
func sample(x, y float64, bg, bg2, fg color.NRGBA) color.NRGBA {
	// Rounded square background.
	const m, rad = 12.0, 52.0
	if !inRoundRect(x, y, m, m, size-m, size-m, rad) {
		return color.NRGBA{}
	}
	// Subtle vertical gradient.
	t := (y - m) / (size - 2*m)
	c := color.NRGBA{lerp(bg.R, bg2.R, t), lerp(bg.G, bg2.G, t), lerp(bg.B, bg2.B, t), 0xff}
	// Check mark: two thick segments.
	if segDist(x, y, 62, 138, 112, 188) < 17 || segDist(x, y, 112, 188, 200, 84) < 17 {
		return fg
	}
	// Signal dot in the top-right corner.
	if math.Hypot(x-196, y-60) < 15 {
		return fg
	}
	return c
}

func lerp(a, b uint8, t float64) uint8 { return uint8(float64(a) + (float64(b)-float64(a))*t) }

func inRoundRect(x, y, x0, y0, x1, y1, r float64) bool {
	if x < x0 || x > x1 || y < y0 || y > y1 {
		return false
	}
	cx := math.Max(x0+r, math.Min(x, x1-r))
	cy := math.Max(y0+r, math.Min(y, y1-r))
	return math.Hypot(x-cx, y-cy) <= r
}

func segDist(px, py, x0, y0, x1, y1 float64) float64 {
	dx, dy := x1-x0, y1-y0
	t := ((px-x0)*dx + (py-y0)*dy) / (dx*dx + dy*dy)
	t = math.Max(0, math.Min(1, t))
	return math.Hypot(px-(x0+t*dx), py-(y0+t*dy))
}
