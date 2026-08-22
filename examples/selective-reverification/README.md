# Selective Reverification example

Merge this object's fields under the optional `continuity` key of an
`openline.check.v1` check pack.

Changing `artifact:patch` reopens `tests-standing` and its descendant
`merge-ready`, while `review-standing` remains standing. Only the `tests`
evidence artifact is withheld from Receipt Gate.

Changing an unrelated root reopens nothing.
