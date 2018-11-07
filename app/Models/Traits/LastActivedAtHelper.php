<?php

namespace App\Models\Traits;

use Redis;
use Carbon\Carbon;

trait LastActivedAtHelper
{
    // 缓存相关
    protected $hash_prefix = 'larabbs_last_actived_at_';
    protected $field_prefix = 'user_';

    public function recordLastActivedAt()
    {
        // 获取今天的日期
        $date = Carbon::now()->toDateString();

        // Redis哈希表的命名，如：larabbs_last_actived_at_2018_11_07
        $hash = $this->hash_prefix . $date;

        // 字段名称，如：user_1
        $field = $this->field_prefix . $this->id;

        // 当前时间，如：2018-11-07 19:38:00
        $now = Carbon::now()->toDateTimeString();

        // 数据写入Redis，字段已存在会被更新
        Redis::hSet($hash, $field, $now);
    }
}