## 数据结构和对象
> Redis中的每个键值对的键都是字符串对象，值可以是：字符串对象、列表对象、哈希对象、集合对象、有序集合对象。<br>
### SDS（simple dynamic string）
#### 1.Redis中使用的字符串都是SDS，结构如下：
``` C++
struct sdshdr {
    int len;
    int free;
    char buf[];
}
```
#### 2.减少空间重分配次数
预分配
- 如果SDS修改后len小于1MB，那么分配和len同样大小的未使用空间；
- 如果SDS修改后len大于等于1MB，那么分配1MB的未使用空间。

惰性释放
- SDS缩短后，不会立即释放回收缩短后的字节，而是用free记录。

#### 二进制安全
buf被当做字符数组处理而不是C字符串。

#### SDS API
![](https://github.com/CodeDrugger/Learning/raw/master/REDIS/pic/0x01.png)

### 链表
带头尾指针的双向列表
``` C++
typedef struct listNode {
    // 前置节点
    struct listNode *prev;
    // 后置节点
    struct listNode *next;
    // 节点的值
    void *value;
} listNode;

typedef struct list {
    // 表头节点
    listNode *head;
    // 表尾节点
    listNode *tail;
    // 链表所包含的节点数量
    unsigned long len;
    // 节点值复制函数
    void *(*dup)(void *ptr);
    // 节点值释放函数
    void (*free)(void *ptr);
    // 节点值对比函数
    int (*match)(void *ptr, void *key);
} list;
```

### 字典
字典底层用哈希表实现
``` C++
// 哈希表节点
typedef struct dictEntry {
    // 键
    void *key;
    // 值
    union {
        void *val;
        uint64_t u64;
        int64_t s64;
    } v;
    // 指向下个哈希表节点，形成链表
    struct dictEntry *next;
} dictEntry;

// 哈希表
typedef struct dictht {
    // 哈希表数组
    dictEntry **table;
    // 哈希表大小
    unsigned long size;
    // 哈希表大小掩码，用于计算索引值
    // 总是等于 size - 1
    unsigned long sizemask;
    // 该哈希表已有节点的数量
    unsigned long used;
} dictht;

// 字典
typedef struct dict {
    // 类型特定函数 保存一簇用于操作特定类型键值对的函数，Redis会为用途不同的字典设置不同的函数
    dictType *type;
    // 私有数据 保存需要传给那些类型特定函数的可选参数
    void *privdata;
    // 哈希表 通常情况只使用ht[0]，ht[1]在rehash时使用
    dictht ht[2];
    // rehash 索引
    // 当 rehash 不在进行时，值为 -1
    int rehashidx; /* rehashing not in progress if rehashidx == -1 */
} dict;

typedef struct dictType {
    // 计算哈希值的函数
    unsigned int (*hashFunction)(const void *key);
    // 复制键的函数
    void *(*keyDup)(void *privdata, const void *key);
    // 复制值的函数
    void *(*valDup)(void *privdata, const void *obj);
    // 对比键的函数
    int (*keyCompare)(void *privdata, const void *key1, const void *key2);
    // 销毁键的函数
    void (*keyDestructor)(void *privdata, void *key);
    // 销毁值的函数
    void (*valDestructor)(void *privdata, void *obj);
} dictType;
```
拉链发解决冲突<br>
当负载因子ht[0].used / ht[0].size大于等于1（未执行BGSAVE或BGREWRITEOF）或5（执行BGSAVE或BGREWRITEOF）时，执行rehash的扩展操作，扩展的大小为第一个大于ht[0].used*2的2**n；<br>
当负载因子ht[0].used / ht[0].size小于0.1时，执行rehash的收缩操作，收缩的大小为第一个大于ht[0].used的2**n。<br>
rehash采用渐进式：
- 为ht[1]分配空间
- 将rehashidx设置为0，表示rehash开始
- rehash期间，每次对字典执行添加、删除、查找、更新操作时，会将ht[0]，rehashidx上的键值对rehash到ht[1]，并且++rehashidx
- 全部移植完成后，rehashidx设置为-1，表示rehash结束
### 跳跃表
