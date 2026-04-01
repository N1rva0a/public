# Advanced Taint Propagation Methodology (三轮迭代污点追踪) v1.0

## 触发时机
- taint-analyst 子代理在处理任何 CANDIDATE+ finding 时**强制执行三轮迭代**
- 必须在 E3（reachable path）闭合前完成，否则 finding 不得晋升

## 三轮迭代协议（严格顺序执行）

### Round 1: Direct Data Flow（直接数据流）
- 标准 taint 追踪：source → sanitizer → sink
- 记录每一步变量名、方法调用、行号
- 输出：`DirectPath: [source → ... → sink]`

### Round 2: Control Flow + Reflection/DI/Proxy/Decorator/AOP（控制流 + 动态注入）
- 必须主动追踪：
  - Reflection (`Class.forName`, `Method.invoke`, `Constructor.newInstance`)
  - Dependency Injection (`@Autowired`, Spring BeanFactory, Guice, CDI)
  - Proxy / Dynamic Proxy / CGLIB / Decorator 模式
  - AOP (AspectJ, Spring AOP, Interceptor)
  - Metaprogramming (ByteBuddy, ASM, Javassist)
- 追踪路径必须包含**完整调用栈 + 反射入口点**
- 输出：`AdvancedPath-R2: [reflection/di chain]`

### Round 3: Second-order + Async + Persistent + Cache + MQ + LLM contamination（二阶 + 异步 + 持久化污染）
- 追踪以下污染路径：
  - Second-order（DB → Cache/MQ/EventBus → 后续读取）
  - Async（@Async, CompletableFuture, Reactor, Kafka/RabbitMQ consumer）
  - Persistent storage（Redis, Session, File, DB blob）
  - LLM / Agent / Tool-calling 信任边界污染
- 必须验证 taint 是否跨越**边界**（e.g. JSON serialize → deserialize）
- 输出：`AdvancedPath-R3: [second-order/async chain]`

## 输出格式要求
[TAINT_ITERATION_SUMMARY]
Round 1: DirectPath → ...
Round 2: AdvancedPath-R2 → ...
Round 3: AdvancedPath-R3 → ...
Final Taint Closure: [CLOSED / BROKEN] + 关键证据行号

## 与 load_on_demand_map 联动
在 load_on_demand_map.md 中追加：
advanced taint, second-order, reflection taint, async contamination → references/core/advanced_taint_propagation.md


**使用方式**：在 `taint-analyst.md` 中追加一行调用：
> 执行三轮 Advanced Taint Propagation（references/core/advanced_taint_propagation.md）