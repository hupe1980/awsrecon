package recon

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsCDKAssetParameter(t *testing.T) {
	t.Run("ArtifactHash", func(t *testing.T) {
		assert.Equal(t, true, isCDKAssetParameter("AssetParameters561201ae555f9f7fcb7698cc8dea9bc63f3299bf6d160fc68e33fa641cba4c1aArtifactHash9CAB3342"))
	})

	t.Run("S3Bucket", func(t *testing.T) {
		assert.Equal(t, true, isCDKAssetParameter("AssetParameters3b6a0aaf4bd6174635741664e71b38f42bf1727aee81228e86d5081eacc2d287S3BucketE2977EAA"))
	})

	t.Run("S3VersionKey", func(t *testing.T) {
		assert.Equal(t, true, isCDKAssetParameter("AssetParameters3b6a0aaf4bd6174635741664e71b38f42bf1727aee81228e86d5081eacc2d287S3VersionKeyCC7242A2"))
	})
}
