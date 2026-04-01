# Gadget 链枚举检查清单

> 配合 `references/core/gadget_enum.md` 使用。本清单用于逐项追踪枚举进度。

## 入口识别
- [ ] 确认反序列化入口函数及所在文件:行
- [ ] 确认用户可控数据能否到达该入口（追踪 source→unserialize 路径）
- [ ] 确认是否存在 Decode-After-WAF 模式（先解码再反序列化）

## 轨道1: 类加载时序
- [ ] 建立 T时刻可用类集合（通过 require/import 链追踪）
- [ ] 候选类中是否有含危险魔术方法的类（`__wakeup`/`__destruct`/`readObject`）
- [ ] 危险方法是否可串联到危险 sink（eval/exec/file_write/JNDI）
- [ ] 类集合为空 → 记录为 Low（降级）

## 轨道2: 过滤器旁路
- [ ] 反序列化前是否有 WAF/filterData 检查
- [ ] 检查执行时机：在解码前还是解码后
- [ ] 若在解码前 → 记录为过滤器无效（Decode-After-WAF）

## 轨道3: 已知链匹配
- [ ] **PHP**: 运行 `phpggc --list` 与项目依赖交叉对比
- [ ] **Java**: 对比 ysoserial 支持的链与项目 classpath 依赖
  - [ ] commons-collections 3.x/4.x
  - [ ] spring-core / spring-aop
  - [ ] groovy / clojure / bsh
  - [ ] c3p0 (JNDI)
- [ ] 类集合为空时评估 PHP 内置类（SplFileObject/SimpleXMLElement）

## 自定义链分析
- [ ] 搜索所有魔术方法实现，列出清单
- [ ] 对每个魔术方法追踪调用链至 sink
- [ ] 评估是否可从可控属性触发

## 输出
- [ ] 输出 `[PHASE_5B_SUMMARY]` 含三轨结论
- [ ] 标注综合最高威胁路径及置信度
- [ ] 生成或注明 PoC 构造工具（ysoserial/phpggc/手工）
