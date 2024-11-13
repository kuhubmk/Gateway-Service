function checkFeatureLimit(request, session, spec) {
    const meta = session.meta_data;
    const role = meta.role;
    const feature = request.url.split('/').pop();  // 从URL获取功能类型
    
    // 获取该角色对应功能的限制
    const limits = FEATURE_LIMITS[feature][role];
    
    // 检查音频长度（仅针对语音转录）
    if (feature === 'speech-to-text') {
        const audioLength = request.body.audio_length;
        if (audioLength > limits.max_duration) {
            return {
                code: 403,
                message: `Audio length exceeds limit for ${role} users`
            };
        }
    }
    
    // 检查使用次数
    if (limits.daily_limit !== -1) {
        const usageKey = `${meta.user_id}:${feature}:daily`;
        const usage = getUsage(usageKey);
        if (usage >= limits.daily_limit) {
            return {
                code: 429,
                message: `Daily limit exceeded for ${feature}`
            };
        }
        incrementUsage(usageKey);
    }
    
    return null;
} 