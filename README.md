Linux高性能服务器学习
=
## 一.TCP/IP协议
### a.协议层次<br>
1.TCP、IP协议是一个四层的结构：<br>
![](https://github.com/CodeDrugger/HPLSP/raw/master/pic/001.png)
2.数据链路层，常用的协议是ARP协议和RARP协议，实现了IP地址和物理地址之间的转化<br>
3.网络层，常用协议有ICMP、IP<br>
4.传输层，常用协议有TCP、UDP<br>
5.应用层，不举例<br>
### b.协议封装<br>
![](https://github.com/CodeDrugger/HPLSP/raw/master/pic/002.png)
## 二.IP协议
### a.IPV4<br>
1.头部结构：<br>
![](https://github.com/CodeDrugger/HPLSP/raw/master/pic/003.png)
- 4位版本号固定为4；
- 4位头部长度表示头部有多少个4字节，4位最大表示15，所以头部长度最大为60字节；
- 8位服务类型包括：3位的优先权（已废弃），4位的TOS字段（分别表示最小延时，最大吞吐量，最高可用性，最小费用，只能有一个置为1），1位的保留字段（必须为0）；
- 16位总长度指整个报文的长度，单位为字节；
- 16位标识，唯一标识每一个报文，初始值由系统生成，每发一个报文，该值+1，同一个报文的不同分片有相同的值；
- 3位标志包括：1位保留，1位DF（禁止分片），1位MF（更多分片）；
- 13位分片偏移，是分片相对于原始报文开始处（数据部分）的偏移，实际偏移量为该值的8倍，因此除最后一个分片外，其他报文的数据部分的长度必须是8的整数倍；
- 8位生存时间，路由跳数；
- 8位协议，在/etc/protocols中定义；
- 16位头部校验和，CRC校验；
- 32位源IP；
- 32位目的IP；
- 最多40位的扩展信息<br>

2.IP分片<br>
IP报文长度超过数据帧的MTU时，分片；MTU为1500字节，因此携带的最多数据为1480字节<br>
3.IP路由<br>
route命令查看路由表<br>
### b.IPV6
1.头部结构：<br>
![](https://github.com/CodeDrugger/HPLSP/raw/master/pic/004.png)
- 4位版本号固定为6；
- 8位通信类型类似于IPV4的TOS；
- 20位标签流，指示数据优先级，如实时视频；
- 16位净荷长度，指扩展头部和数据部分的长度；
- 8位下一个包头，指出紧跟在固定头部后的包头类型，如扩展头部或上层协议的包头，类似于IPV4的协议字段；
- 8位跳数限制，类似于TTL；
- 128位源地址；
- 128位目的地址；<br>
## 三.TCP协议
### a.特点：面向连接，字节流，可靠传输
### b.头部结构
![](https://github.com/CodeDrugger/HPLSP/raw/master/pic/005.png)
- 16位源端口号；
- 16位目的端口号；
- 32位序号，一次TCP通信某一方向上的字节流的每个字节编号，即当前报文中第一个字节相对于字节流头部的偏移，单位为字节；
- 32位确认号，用作对另一方发来的报文段的响应，其值为收到的报文段的序号+1；
- 4位头部长度，标识该报文头有多少个4字节，TCP报文头最大长度为60字节；
- 6位标志位包括：
  - URG标志，表示紧急指针知否有效；
  - ACK标志，表示确认号是否有效，携带ACK标志的报文为确认报文；
  - PSH标志，提示接收端应立即从缓冲区取走数据；
  - RST标志，要求对方重新建立连接，携带RST标志的报文为复位报文，如访问不存在的端口或一方非正常关闭；
  - SYN标志，表示请求建立连接，携带SYN标志的报文为同步报文；
  - FIN标志，通知对方本端要关闭连接了，携带FIN标志的报文为结束报文；
- 16位窗口大小；
- 16位校验和，CRC校验；
- 16位紧急指针，是一个正的偏移量，是当前报文紧急数据存放处的偏移的下一字节；<br>
### c.三次握手四次挥手
![](https://github.com/CodeDrugger/HPLSP/raw/master/pic/006.png)
### d.半关闭状态
通信的一方发送结束报文给对方，但仍允许接收数据，直到对方也发送了结束报文，这种状态就是半关闭状态<br>
### e.TCP状态转移
![](https://github.com/CodeDrugger/HPLSP/raw/master/pic/007.png)
TIME_WAIT状态是一方收到另一方的结束报文时，不直接关闭，而是等待2个最大报文生存时间，保证连接可靠关闭以及迟到数据正确接收<br>
### f.带外数据
TCP没有真正的带外数据，可以通过紧急指针实现，带外数据只有1字节<br>
### g.超时重传
Linux发送端没收到确认报文时，触发超时重传，每次的间隔时间是上次间隔时间的一倍（从0.2s开始），重传都失败后，IP和ARP协议开始接管，直到发送方主动放弃<br>
重传相关的内核参数为：/proc/sys/net/ipv4/tcp_retries1和/proc/sys/net/ipv4/tcp_retries2，前者确定底层协议接管前的重试次数，后者确定放弃前的重试次数<br>
### h.拥塞控制
拥塞控制包括慢启动、拥塞避免、快速重传、快速恢复<br>
1.慢启动和拥塞避免<br>
- SWND：发送窗口，指一次发送中发送端写入的数据量，该值为RWND和CWND的较小者<br>
- RWND：接收通告窗口<br>
- CWND：拥塞窗口，发送端的控制变量<br>

TCP连接建立好后，CWND被设置为初始值，SWND=CWND，发送后收到确认报文段后CWND=min(N,SMSS)，其中N为确认的报文段的长度，SMSS为发送端最大段大小，初始阶段窗口大小指数增长；<br>
当CWND达到ssthresh后，慢启动结束，进入拥塞控制阶段；<br>
拥塞控制阶段每次收到确认报文段时，CWND+=1，此为拥塞避免<br>
2.快速重传和快速恢复<br>
快速重传根据收到的确认报文判断，如果收到3个重复的确认报文，就立即重传，而不是等到计时器超时才重传；<br>
> 举例：发送端发送了1,2,3三个报文段，3丢失，接收方回复了1,2的确认报文，发送方接着发送了4,5,6报文，发送方仍然回复了3个2报文的确认报文，这时发送端快速重传3，接收方回复6的接收报文<br>

快速恢复即将ssthresh减为CWND的一半（Reno），CWND=ssthresh，重新开始拥塞控制<br>
## Linux网络编程基础API
### a.字节序转换
``` C++
#include <netinet/in.h>
unsigned long int htonl(unsigned long int hostlong); //host to network long
unsigned long int ntohl(unsigned long int netlong); //network to host long
```
### b.TCP专用地址结构体
``` C++
struct sockaddr_in {
short sin_family; //Address family一般来说AF_INET（地址族）PF_INET（协议族）
unsigned short sin_port; //Port number(必须要采用网络数据格式,普通数字可以用htons()函数转换成网络数据格式的数字)
struct in_addr sin_addr; //IP address in network byte order（Internet address）
unsigned char sin_zero[8]; //Same size as struct sockaddr没有实际意义,只是为了　跟SOCKADDR结构在内存中对齐
};

struct in_addr {
u_int32_t s_addr;
};
```
### c.点分十进制和整数的转化
``` C++
#include <arpa/inet.h>
in_addr_t inet_addr(const char* strptr); //点分十进制转化为整数
int inet_aton(const char* cp, struct in_addr* inp); //点分十进制转化为整数，结果放在inp中，成功返回1，失败返回0
char* inet_ntoa(struct in_addr in); //整型转化为点分十进制
```
### d.创建socket
``` C++
#include <sys/types.h>
#include <sys/socket.h>
/*
domain：使用哪个底层协议PF_INET IPV4 PF_INET6 IPV6
type：使用哪个服务类型，SOCK_STREAM流服务 SOCK_UGRAM数据报
type接受上述值与SOCK_NONBLOCK（非阻塞） SOCK_CLOEXEC（使用fork创建子进程时关闭该socket）相与
protocol默认0
失败返回-1
*/
int socket(int domain, int type, int protocol);
```
### e.绑定socket
``` C++
/*
my_addr：需要绑定的socket地址
sockfd：需要绑定的文件描述符
addrlen：需要绑定的socket地址的长度
成功返回0，失败返回-1
*/
int bind(int sockfd, const struct sockaddr* my_addr, socklen_t addrlen);
```
### f.监听socket
创建监听队列存放待处理的客户连接
``` C++
#include <sys/socket.h>
/*
sockfd：被监听的socket
backlog：监听队列的长度，典型值是5
*/
int listen(int sockfd, int backlog);
```
### g.接收连接
从listen的监听队列中获取一个连接
``` C++
#include <sys/types.h>
#include <sys/socket.h>
/*
sockfd：是执行过listen的socket
addr：用来获取被接受连接的远端socket地址
addrlen：指出远端socket地址的长度
失败时返回-1
*/
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
```
### h.发起连接
``` C++
#include <sys/types.h>
#include <sys/socket.h>
/*
sockfd：由socket返回一个socket
serv_addr：服务器监听的socket地址
addrlen：是个地址的长度
成功返回0
*/
int connect(int sockfd, const struct sockaddr* serv_addr, socklen_t addrlen);
```
### i.关闭连接
并非立即关闭连接，而是将fd的引用计数-1，只有当fd的引用计数为0时，才会真正关闭。<br>
多进程程序中，一次fork默认将系统已打开的socket引用计数+1，只有在父进程和子进程中都调用close()才能关闭连接
``` C++
#include <unistd.h>
/*
fd：待关闭的连接
*/
int close(int sockfd);
```

无论如何都要立即终止连接，可使用：<br>
``` C++
#include <socket.h>
/*
fd：待关闭的连接
howto：
  SHUT_RD：关闭sockfd上读的一半，程序不能再对其进行读操作，接收缓冲区的数据将被丢弃
  SHUT_WR：关闭sockfd上写的一半，缓冲区中的数据会在真正关闭连接之前全部发送出去，程序不能再对其进行写操作，这种情况下，socket处于半关闭状态
  SHUT_RDWR：读写同时关闭
*/
int shutdown(int sockfd, int howto);
```
### j.数据读写
文件读写操作read()和write()同样适用socket，socket接口提供了专用的系统调用<br>
#### TCP数据读写
``` C++
/*
sockfd：需要读取的文件描述符
buf：读缓冲区
len：读缓冲区的大小
flags：通常为0，具体见后图
调用成功时返回实际读取到的长度，返回0表示对方已经关闭了连接，-1表示出错
*/
ssize_t recv(int sockfd, void *buf, size_t len, int flags);

/*
sockfd：需要写入的文件描述符
buf：写缓冲区
len：写缓冲区的长度
flags：通常为0，具体见后图
*/
ssize_t send(int sockfd, const void *buf, size_t len, int flags);
```
#### UDP数据读写
TCP连接也可以调用，调用时地址填NULL
``` C++
/*
sockfd：需要读取的文件描述符
buf：读缓冲区
len：读缓冲区的大小
flags：通常为0，具体见后图
src_addr：发送端socket地址
addrlen：发送端socket地址长度
*/
ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr* src_addr, socklen_t * addrlen);

/*
sockfd：需要写入的文件描述符
buf：写缓冲区
len：写缓冲区的长度
flags：通常为0，具体见后图
dest_addr：接收端socket地址
addrlen：接收端socket地址长度
*/
ssize_t sendto(int sockfd, void *buf, size_t len, int flags, struct sockaddr* dest_addr, socklen_t * addrlen);
```
#### 通用数据读写
TCP/UDP都适用<br>
对于读取来说，数据将被读取并存放在msg_iovlen块分散的内存块中，这些内存的位置和长度由msg_iov指定，这称为分散读；<br>
对于写入来说，msg_iovlen块分散内存中的数据将被一并发送，这称为集中写<br>
``` C++
/*
sockfd：需要读取的文件描述符
msg：见后
flags：通常为0，具体见后图
*/
ssize_t recvmsg(int sockfd, struct msghdr* msg, int flags);

/*
sockfd：需要写入的文件描述符
msg：见后
flags：通常为0，具体见后图
*/
ssize_t sendmsg(int sockfd, struct msghdr* msg, int flags);

struct msghdr
{
    void* msg_name; //socket地址
    socklen_t msg_namelen; //socket地址的长度
    struct iovec* msg_iov; //分散内存块，见后
    int msg_iovlen; //分散内存块的数量
    void* msg_control; //指向辅助数据的起始位置
    socklen_t msg_controllen; //辅助数据的大小
    int msg_flags; //复制函数中的flags参数，并在调用过程中更新
};

struct iovec
{
    void* iov_base; //内存块起始地址
    size_t iov_len; //内存块长度
}
```
![](https://github.com/CodeDrugger/HPLSP/raw/master/pic/008.png)
### k.带外数据
内核通知应用程序带外数据到来的方式通常有I/O复用产生的异常事件和SIGURG信号，应用程序可以通过如下系统调用知道带外数据在数据流中的位置：<br>
``` C++
#include <sys/socket.h>
/*
sockfd：待判断的socket文件描述符
返回1时就可以利用带MSG_OOB标志的recv调用来接收带外数据，如果不是就返回0
*/
int sockatmark(int sockfd);
```
### l.地址信息函数
用于获取一个socket连接的本端socket地址或远端socket地址，可以使用下面两个系统调用<br>
``` C++
#include <sys/socket.h>
/*
sockfd：需要获取的socket对应的文件描述符
address：获取到的地址将存储于address指定的内存
address_len：address的长度
*/
int getsockname(int sockfd, struct sockaddr* address, socklen_t * address_len);
/*
sockfd：需要获取的socket对应的文件描述符
address：获取到的地址将存储于address指定的内存
address_len：address的长度
*/
int getpeername(int sockfd, struct sockaddr* address, socklen_t * address_len);
```
### m.socket选项
用来读取和设置socket文件描述符属性的方法<br>
``` C++
#include <sys/socket.h>
/*
sockfd：指定被操作的socket
level：指定要操作哪个协议的选项
option_name：指定选项的名字
option_value：被操作选项的值
option_len：被操作选项的值的长度，restrict表示该指针是访问对象的唯一指针
成功时返回0，失败返回-1
*/
int getsockopt(int sockfd, int level, int option_name, void* option_value, socklen_t* restrict option_len);
int setsockopt(int sockfd, int level, int option_name, const void* option_value, socklen_t option_len);
```
![](https://github.com/CodeDrugger/HPLSP/raw/master/pic/009.png)
SO_REUSEADDR：设置该选项强制使用被处于TIME_WAIT状态的连接占用的socket地址<br>
SO_RCVBUF、SO_SNDBUF：设置TCP接收缓冲区和发送缓冲区的大小，设置后系统通常会将其加倍，并且不得小于某个值<br>
SO_RCVLOWAT、SO_SNDLOWAT：分别表示TCP接收缓冲区和发送缓冲区的低水位标记，一般被IO复用系统调用用来判断socket是否可读或可写，当接收缓冲区的数据大于标记时，IO复用通知应用程序可读取数据，当发送缓冲区的空闲空间大于标记时，IO复用通知应用程序可写入数据，通常都是1<br>
SO_LINGER：用于控制close系统调用在关闭TCP连接时的行为，设置该选项时，需要传一个linger类型的结构体：<br>
``` C++
#include <sys/socket.h>
struct linger
{
    int l_onoff; //开启（非0）还是关闭（0）该选项
    int l_linger; // 滞留时间
}
```
- l_onoff等于0时，SO_LINGER选项不起作用，close使用默认行为关闭socket
- l_onoff不为0，l_linger为0时，close立即返回，TCP模块丢弃发送缓冲区中的数据，并发送复位报文段
- l_onoff不为0，l_linger大于0时，
  - 对于阻塞的socket，close等待l_linger长的时间，直到TCP模块发送所有残留数据并得到对方确认，如果没有完成，close返回-1，并置errno为EWOULDBLOCK
  - 对于非阻塞socket，close立即返回，需要根据errno的值判断是否已经发送完毕<br>
### n.网络信息API
``` C++
#include <netdb.h>
struct hostent
{
    char* h_name; //主机名
    char** h_aliaases; //主机名列表
    int h_addrtype; //地址类型
    int h_length; //地址长度
    char** h_addr_list; //按网络字节序列出的IP地址列表
}

/*
name：主机名
*/
struct hostent* gethostbyname(const char* name);

/*
addr：目标主机的IP地址
len：addr所指IP地址的长度
type：addr所指IP地址的类型（AF_INET:IPV4或AF_INET6:IPV6）
*/
struct hostent* gethostbyaddr(const void* addr, size_t len, int type);
```
``` C++
#include <netdb.h>
/*
name：指定目标服务的名字
proto：指定服务类型
*/
struct servent* getservbyname(const char* name, const char* proto);

/*
port：指定目标服务对应的端口号
proto：指定服务类型
*/
struct servent* getservbyport(int port, const char* proto);

struct servent
{
    char* s_name; //服务名称
    char** s_aliases; //服务的别名列表
    int s_port; //端口号
    char* s_proto; //服务类型，通常是TCP或UDP
}
```
## 四.高级I/O函数
### pipe函数
用于创建一个管道，实现进程间通信，fd[1]写入数据，fd[0]读出数据，默认读写都是阻塞的<br>
``` C++
#include <unistd.h>
/*
成功时返回0，并将一对打开的文件描述符填入其参数指向的数组
*/
int pipe(int fd[2])
```
socketpair可以创建双向管道
``` C++
#include <sys/types.h>
#include <sys/socket.h>
/*
domain：只能用UNIX本地域协议族AF_UNIX，只能在本地使用这个双向管道
type、protocol和socket函数相同，fd[2]和pipe相同
*/
int socketpair(int domain, int type, int protocol, int fd[2]);
```
### dup函数和dup2函数
把标准输入重定向到一个文件或把标准输出重定向到一个网络连接<br>
``` C++
#include <unistd.h>
/*
file_descriptor：需要重定向的文件描述符
调用失败返回-1，调用成功返回文件描述符，该文件描述符是当前可用的最小整数值
*/
int dup(int file_descriptor);

/*
file_descriptor_one：需要重定向的文件描述符
file_descriptor_two：表示返回的文件描述符不小于该值
调用失败返回-1，调用成功返回不小于file_descriptor_two的文件描述符
*/
int dup2(int file_descriptor_one, int file_descriptor_two);
```
dup函数创建一个新的文件描述符，该文件描述符和源文件描述符file_descriptor指向相同的文件、管道或网络连接，[示例代码](https://github.com/CodeDrugger/HPLSP/blob/master/code/dup.cpp)<br>
### readv函数和writev函数
readv函数将数据从文件描述符读到分散内存块中，即分散读，writev函数则将多块分散内存数据一并写入文件描述符中<br>
``` C++
#include <sys/uio.h>
/*
fd：被操作的文件描述符
vector：iovec数组，iovec描述一块内存
count：vector数组的长度
调用成功返回读/写的字符数，失败返回-1
*/
ssize_t readv(int fd, const struct iovec* vector, int count);
ssize_t writev(int fd, const struct iovec* vector, int count);
```
### sendfile函数
在两个文件描述符中直接传递数据，完全在内核中操作，从而避免了内核缓冲区和用户缓冲区之间的数据拷贝，效率很高<br>
``` C++
#include <sys/sendfile.h>
/*
in_fd：待读出内容的文件描述符，支持类似mmap函数的文件描述符，不能是管道或socket
out_fd：待写入内容的文件描述符，必须是socket
offet：指定读入文件流的位置
count：指定传输的字节数
调用成功返回传输字节数，调用失败返回-1
*/
sszie_t sendfile(int out_fd, int in_fd, off_t* offset, size_t count);
```
### mmap和munmap函数
mmap函数用于申请一段内存，是一种内存映射文件的方法，也可用于进程间通信，munmap用于释放mmap申请的内存<br>
``` C++
#include <sys/mman.h>
/*
start：允许用户使用某个特定的地址作为申请内存的起始地址，为NULL时系统自动分配地址
length：指定内存段的长度
prot：指定内存短的访问权限，可取PROT_READ（内存短可读）、PROT_WRITE（内存短可写）、PROT_EXEC（内存段可执行）、PROT_NONE（内存段不能被访问）的按位或
flag：控制内存段被修改后的程序行为
fd：被映射文件对应的文件描述符
offset：指定从文件的何处开始映射
调用成功返回指向目标区域的指针，失败返回-1
*/
void* mmap(void* start, size_t length, int prot, int flags, int fd, off_t offset);
```
flags的常用值以及含义：<br>
![](https://github.com/CodeDrugger/HPLSP/raw/master/pic/010.png)
### splice函数
用于在两个文件描述符之间移动数据，是零拷贝操作
``` C++
#include <fcntl.h>
/*
fd_in：是待输入数据的文件描述符
off_in：如果fd_in是一个管道文件描述符，off_in必须为NULL，如果不是，off_in指定从输入数据流的何处开始读取数据，此时如果off_in是NULL，表示从当前便宜开始读取
fd_out、off_out和fd_in、off_in定义一致，不过用于输出流
len：指定移动数据的长度
flags：控制数据如何移动，可以设置为下图某些值的按位或
fd_in和fd_out必须至少有一个是管道文件描述符，调用成功返移动的字节数，返回0表示没有数据移动，失败返回-1
*/
ssize_t splice(int fd_in, loff_t* off_in, int fd_out, loff_t* off_out, size_t len, unsigned int flags);
```
![](https://github.com/CodeDrugger/HPLSP/raw/master/pic/011.png)
### tee函数
在两个管道文件描述符之间复制数据，是零拷贝操作，它不消耗数据，源文件描述符上的数据仍然可以用作后续的读操作
``` C++
#include <fcntl.h>
/*
fd_in：待输入数据的文件描述符，必须是管道
fd_out：待读出数据的文件描述，必须是管道符
len：复制的字节数
flags：同splice函数
调用成功返回复制的字节数，失败返回-1
*/
sszie_t tee(int fd_in, int fd_out, size_t len, unsigned int flags);
```
### fcntl函数
提供对文件描述符的各种操作控制
``` C++
#include <fcntl.h>
/*
fd：被操作的文件描述符
cmd：指定执行何种类型的操作
第三个参数可选
*/
int fcntl(int fd, int cmd, ... );
```
![](https://github.com/CodeDrugger/HPLSP/raw/master/pic/012.png)<br>
通常用作将一个文件描述符设置为非阻塞的：
``` C++
#include <fcntl.h>
int setnoblocking(int fd) {
    int old_option = fcntl(fd, F_GETFL);
    int new_option = old_option | O_NONBLOCK;
    fcntl(fd, F_SETFL, new_option);
    return old_option;
}
```
## 五.linux服务器程序规范
### 用户信息
UID：真实用户ID
EUID：有效用户ID，存在的目的是方便资源访问，它使得运行程序的用户拥有该程序的有效用户的全效，有效用户为root的进程称为特权进程
GID：真实组ID
EGID：有效组ID，和EUID类似，给运行目标程序的组用户提供有效权限
### 进程间关系
#### 进程组
Linux下每一个进程都隶属于一个进程组，进程除了PID信息外，还有进程组PGID<br>
每个进程组都有一个首领进程，其PGID=PID，进程组一直存在，直到其中的所有进程都退出或加入其它进程组
``` C++
#include <unistd.h>
pid_t getpgid(pid_t pid);
/*
把pid的PGID设置为pgid，当pid为0时，表示设置当前进程
只能设置自己的或其子进程的PGID
调用成功返回0，失败返回-1
*/
int setpgid(pid_t pid, pid_t pgid);
```
#### 会话
一些有关联的进程组将形成一个会话，用下面的函数创建会话：
``` C++
#include <ubistd.h>
/*
调用成功返回新进程组的PGID
*/
pid_t setsid(void)
```
该函数不能由进程组的首领进程调用，对于非首领进程，调用该函数还有如下效果：
- 调用进程成为会话的首领，此时该进程是会话的唯一进程
- 新建一个进程组，其PGID就是调用进程的PID，调用进程称为该进程组的首领
- 调用进程将甩开终端

Linux未提供会话ID的概念，Linux认为它等于会话首领进程所在的进程组的PGID
### 改变工作目录和根目录
获取当前进程的工作目录、改变进程的工作目录、改变进程根目录的函数分别是，只有特权进程才能改变根目录：
``` C++
#include <unistd.h>
char* getcwd(char* buf, size_t size);
int chdir(const char* dir);
int chroot(const char* path);
```
### 服务器程序后台化
``` C++
#include <unistd.h>
/*
nochdir：传0时根目录被置为/
noclose：传0时标准输入、标准输出、标准错误被重定向到/dev/null
*/
int daemon(int nochdir, int noclose)
```
## 六.高性能服务器程序框架
### 两种高效的事件处理模式
#### Reactor模式
要求主线程只负责监听文件描述符上是否有事件发生，有的话就立即通知工作线程，除此之外，主线程不做任何其他实质性的工作。数据读写，接收新的连接，处理客户请求均在工作线程中完成。
