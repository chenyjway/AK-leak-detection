# AK-leak-detection

收集企业内部所有的AccessKeyId作为关键特征，借助 Github API 强大的代码搜索能力，通过定时任务检测关键特征，以发现可能的AK/SK泄露事件。



（1）工具运行：

![](.\images\1-1.png)

（2）邮件告警：

![](.\images\1-2.png)



（3）Syslog集成