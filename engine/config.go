package engine

/**
 * @author: yasinWu
 * @date: 2022/1/13 13:29
 * @params: fingerRatio int
 * @return: Option
 * @description: 配置指纹相似度
 */
func WithFingerRatio(fingerRatio int) Option {
	return func(dsiEngine *DsiEngine) {
		if fingerRatio > 0 {
			dsiEngine.fingerRatio = fingerRatio
		}
	}
}

/**
 * @author: yasinWu
 * @date: 2022/1/13 13:30
 * @params: snapLength int
 * @return: Option
 * @description: 配置告警信息快照长度
 */
func WithSnapLength(snapLength int) Option {
	return func(dsiEngine *DsiEngine) {
		if snapLength > 0 {
			dsiEngine.snapLength = snapLength
		}
	}
}

/**
 * @author: yasinWu
 * @date: 2022/1/13 13:30
 * @params: attachLength int
 * @return: Option
 * @description: 配置附件信息长度
 */
func WithAttachLength(attachLength int) Option {
	return func(dsiEngine *DsiEngine) {
		if attachLength > 0 {
			dsiEngine.attachLength = attachLength
		}
	}
}
