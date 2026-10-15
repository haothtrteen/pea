# PEA 首页结构映射

此表用于说明为什么页面会让熟悉 REA 官网的用户认出结构上的对应关系，同时区分 PEA 自己的产品内容。

| REA 官网可见区域 | PEA 对应区域 | PEA 的内容变化 |
|---|---|---|
| Top navigation / On this page | 品牌导航、页内目录 | 保持开发者工具站点的熟悉导航模式，品牌与链接独立设计 |
| Hero: Find out how software works | Hero: 让软件保护成为可验证的工程 | 将“理解程序”换为“规划保护并验证” |
| Set up REA / copy prompt / CLI command | 开始使用 PEA / 复制工作流 prompt / 离线原型命令 | 不伪造尚不存在的安装器；命令来自现有的 Python 离线规划器 |
| What is reverse engineering? | 什么是软件保护工程？ | 以客户端核心算法暴露面引出具体问题 |
| Before REA / With REA | 没有 PEA / 使用 PEA | 对应手工调查与有证据的保护规划工作流 |
| Dinosaur-game example | 原生代码保护路径选择器 | 让读者根据目标平台与保护目标切换教学用候选清单 |
| Calculator example | 发布产物示例审计 | 在 APK、ASAR、ELF 之间切换模拟检查项 |
| Try REA on a small app | 先试 PEA 的本地离线规划器 | 提供当前已存在的命令与预期结果 |
| Want to go deeper / target guides | 原生代码、前端/桌面、构建与验证专题 | 内容围绕保护规划与验证 |
| FAQ / Community | FAQ / 项目与社区 | 明确 PEA 与 REA 的独立关系，避免造成官方合作误解 |

## 当前网站中明确标注的原型边界

交互选择器不会读取文件或调用保护后端；审计列表是静态示例。所有介绍均区分现有原型和后续计划能力。
