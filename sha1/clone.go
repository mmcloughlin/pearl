package sha1

// Clone returns a copy of d.
func (d *Digest) Clone() *Digest {
	d2 := new(Digest)
	*d2 = *d
	return d2
}
