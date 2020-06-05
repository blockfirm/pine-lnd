// +build kvdb_etcd

package etcd

// readWriteCursor holds a reference to the cursors bucket, the value
// prefix and the current key used while iterating.
type readWriteCursor struct {
	// bucket holds the reference to the parent bucket.
	bucket *readWriteBucket

	// prefix holds the value prefix which is in front of each
	// value key in the bucket.
	prefix string

	// currKey holds the current key of the cursor.
	currKey string
}

func newReadWriteCursor(bucket *readWriteBucket) *readWriteCursor {
	return &readWriteCursor{
		bucket: bucket,
		prefix: string(makeValuePrefix(bucket.id)),
	}
}

// First positions the cursor at the first key/value pair and returns
// the pair.
func (c *readWriteCursor) First() (key, value []byte) {
	// Get the first key with the value prefix.
	kv, err := c.bucket.tx.stm.First(c.prefix)
	if err != nil {
		// TODO: revise this once kvdb interface supports errors
		return nil, nil
	}

	if kv != nil {
		c.currKey = kv.key
		// Chop the prefix and return the key/value.
		return []byte(kv.key[len(c.prefix):]), []byte(kv.val)
	}

	return nil, nil
}

// Last positions the cursor at the last key/value pair and returns the
// pair.
func (c *readWriteCursor) Last() (key, value []byte) {
	kv, err := c.bucket.tx.stm.Last(c.prefix)
	if err != nil {
		// TODO: revise this once kvdb interface supports errors
		return nil, nil
	}

	if kv != nil {
		c.currKey = kv.key
		// Chop the prefix and return the key/value.
		return []byte(kv.key[len(c.prefix):]), []byte(kv.val)
	}

	return nil, nil
}

// Next moves the cursor one key/value pair forward and returns the new
// pair.
func (c *readWriteCursor) Next() (key, value []byte) {
	kv, err := c.bucket.tx.stm.Next(c.prefix, c.currKey)
	if err != nil {
		// TODO: revise this once kvdb interface supports errors
		return nil, nil
	}

	if kv != nil {
		c.currKey = kv.key
		// Chop the prefix and return the key/value.
		return []byte(kv.key[len(c.prefix):]), []byte(kv.val)
	}

	return nil, nil
}

// Prev moves the cursor one key/value pair backward and returns the new
// pair.
func (c *readWriteCursor) Prev() (key, value []byte) {
	kv, err := c.bucket.tx.stm.Prev(c.prefix, c.currKey)
	if err != nil {
		// TODO: revise this once kvdb interface supports errors
		return nil, nil
	}

	if kv != nil {
		c.currKey = kv.key
		// Chop the prefix and return the key/value.
		return []byte(kv.key[len(c.prefix):]), []byte(kv.val)
	}

	return nil, nil
}

// Seek positions the cursor at the passed seek key.  If the key does
// not exist, the cursor is moved to the next key after seek.  Returns
// the new pair.
func (c *readWriteCursor) Seek(seek []byte) (key, value []byte) {
	// Return nil if trying to seek to an empty key.
	if seek == nil {
		return nil, nil
	}

	// Seek to the first key with prefix + seek. If that key is not present
	// STM will seek to the next matching key with prefix.
	kv, err := c.bucket.tx.stm.Seek(c.prefix, c.prefix+string(seek))
	if err != nil {
		// TODO: revise this once kvdb interface supports errors
		return nil, nil
	}

	if kv != nil {
		c.currKey = kv.key
		// Chop the prefix and return the key/value.
		return []byte(kv.key[len(c.prefix):]), []byte(kv.val)
	}

	return nil, nil
}

// Delete removes the current key/value pair the cursor is at without
// invalidating the cursor.  Returns ErrIncompatibleValue if attempted
// when the cursor points to a nested bucket.
func (c *readWriteCursor) Delete() error {
	// Get the next key after the current one. We could do this
	// after deletion too but it's one step more efficient here.
	nextKey, err := c.bucket.tx.stm.Next(c.prefix, c.currKey)
	if err != nil {
		return err
	}

	// Delete the current key.
	c.bucket.tx.stm.Del(c.currKey)

	// Set current key to the next one if possible.
	if nextKey != nil {
		c.currKey = nextKey.key
	}

	return nil
}
