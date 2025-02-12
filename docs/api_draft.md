# api草案：

## 严正声明

坚决抵制添加其它花哨的专门供机场主使用的功能。你们机场主利用本作赚钱又不给我们开发者钱，凭啥给你干活。

我们这些api都是给 自用 / 【共享主】用的，不是给【机场主】用的。

本作就算共享，也仅限于内网测试自娱自乐，如果你用于公网，作者不会帮助你。

## 考量

本作叫做 verysimple，不叫 very complex，一切从简。所以本作也不使用protobuf以及grpc。也不使用复杂的auth方式。

## 详情

使用 https + basic auth + (plain text)/(json)

api在不复杂时，可以使用纯空格、换行符 分隔的字符串形式 (plain text) or toml/json.

### 功能列表
1. 生成toml配置文件功能【已实现】
2. 动态调节当前运行时 所用的 LogLevel 【已实现】
3. 查看本次程序开始运行起所使用的流量（双向）【已实现下载流量查询】
4. 查看自某一天开始所用掉的总流量
5. 动态插入一个 新 inServer / outClient；【已实现】
6. 动态修改 某个 inServer/outClient 的 uuid
7. 动态调节 hy手动挡阻控模式 的发送速率【已实现】
8. 动态删除一个 inServer /outClient【已实现】
9. 动态控制每一个 inServer / outClient 的网速上限 （不太好实现）

其它小功能
1. 生成uuid【已实现】
2. 生成随机证书 以及对应私钥【已实现】

上面的已实现是说交互模式已实现，apiServer的话目前只实现了基本状态查询功能

# 原始函数、命令行 与 API的关系

每一个API都尽量有对应的原始golang函数, 然后命令行命令与 api都会调用该原始函数。

我们每一个API，在API功能允许的情况下，都应该要有对应的命令行参数，可在程序刚运行时就返回一个字符串结果

本作规定，原始函数、命令行 与 API 这三个功能 的go文件 全部放在 项目根目录。

