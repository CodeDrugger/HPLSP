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
#### Proactor模式
将所有的IO操作交给主线程和内核来处理，工作线程只负责业务逻辑
### 两种高效的并发模式
#### 半同步/半异步模式
同步线程用于处理客户逻辑，异步线程用于处理I/O事件，异步线程监听到客户请求后，就将其封装成请求对象并插入到请求队列中，请求队列将通知某个工作在同步模式的工作线程来读取并处理该请求对象。
#### 领导者/追随者模式
多个工作线程轮流获得工作线程合集，轮流监听并处理事件的一种模式，在任意时间点，程序都仅有一个领导者线程。他负责监听I/O事件，其他线程都是追随者。当前领导者检测到I/O事件后，首先从线程池中推选出新的领导者，然后处理I/O事件。
### 提高服务器性能的其他建议
a.池：线程池、进程池<br>
b.数据复制：避免不必要的数据复制<br>
c.上下文切换和锁：减少线程、进程切换的开销，减少锁的使用，降低锁的粒度<br>
## 七.I/O复用
### select系统调用
在一段时间内，监听用户感兴趣的文件描述符上的可读、可写、异常事件。
``` C++
#include <sys/select.h>
/*
nfds：指定被监听的文件描述符总数
readfds、writefds、writefds分别指向可读、可写、异常事件对应的文件描述符集合，程序返回时修改他们通知应用程序 哪些文件描述符已就绪
timeout：超时时间
调用成功返回就绪的文件描述符数，失败返回-1
*/
int select(int nfds, fd_set* readfds, fd_set* writefds, fd_set* writefds, struct timeval* timeout);
```
fd_set时long类型数组，每一个元素的每一位表示一个文件描述符，访问通常通过下列宏完成：
``` C++
#include <sys/select.h>
FD_ZEROS(fd_set *fdset); //清除fdset的所有位
FD_SET(int fd, fd_set *fdset); //设置fd
FD_CLR(int fd, fd_set *fdset); //清除fd
int FD_ISSET(int fd, fd_set *fdset); //检测fdset的是否设置fd

struct timeval {
    long tv_sec; //秒
    long tv_usec; //微秒
};
```
### poll系统调用
与select类似，也是指定时间内轮询一定数量的文件描述符，测试其中是否有就绪者。
``` C++
#include <poll.h>
/*
nfds：fds的大小
timeout：单位为毫秒的超时时间
*/
int poll(struct pollfd *fds, nfds_t nfds, int timeout);
```
pollfd结构如下，它指定所有我们感兴趣的文件描述符上发生的可读、可写、异常事件。
``` C++
struct pollfd {
    int fd;
    short events; //注册的时间
    short revents; //实际发生的事件，有内核填充，通知应用程序fd上实际发生了哪些事件
};
```
events告诉poll监听fd上的哪些事件，它是一系列事件的按位或，如下图：
![](https://github.com/CodeDrugger/HPLSP/raw/master/pic/013.png)<br>
### epoll系统调用
epoll是Linux特有的I/O复用函数，epoll把用户关心的文件描述符放在内核的一个时间列表里，epoll需要一个额外的文件描述符，来唯一标识内核中的事件表，这个文件描述符使用如下函数创建：
``` C++
#include <sys/epoll.h>
/*
size：目前不起作用，只是给内核一个提示，告诉它事件表要多大
返回的文件描述符用作其他epoll系统调用的第一个参数，指定要访问的内核事件表
*/
int epoll_create(int size);
```
用下面的函数操作内核事件表：
``` C++
/*
op：操作类型，包括EPOLL_CTL_ADD（往事件表中注册fd上的事件）、EPOLL_CTL_MOD（修改fd上的注册事件）、EPOLL_CTL_DEL（删除fd上的注册事件）
fd：要操作的文件描述符
调用成功返回0，失败返回-1
*/
int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
```
event指定事件，epoll_event定义如下：
``` C++
struct epoll_event {
    __uint32_t events; //epoll事件
    epoll_data_t data; //用户数据
};
```
表示epoll事件类型的宏是在poll对应的宏前加E，epoll有额外的事件类型EPOLLET和EPOLLONESHOT。data用于存储用户数据，定义如下：
``` C++
typedef union epoll_data {
    void *ptr;
    int fd;
    uint32_t u32;
    uint64_t u64;
} epoll_data_t;
```
四个事件中用的最多的是fd，指定事件从属的目标描述符。如果要将文件描述符和用户数据关联，可以使用ptr指向的用户数据中包含fd。<br>
epoll系列系统调用主要接口是epoll_wait函数，它在一段超时时间内等待一组文件描述符上的事件，原型如下：
```  C++
#include <sys/epoll.h>
/*
events：检测到事件后就将所有的就绪事件从内核事件表复制到events函数中
maxevents：指定最多监听多少个事件
*/
int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout);
```
### LT和ET模式
epoll对文件描述符的操作有两种，LT（Level Trigger，电平触发）和ET（Edge Trigger，边沿触发），LT模式时epoll相当于一个高效的poll，ET是epoll的高效工作模式。<br>
对于LT模式，当epoll_wait检测到其上有事件发生并将此事件通知给应用程序后，应用程序可以不立即处理该事件，当应用程序下一次调用epoll_wait时，epoll_wait还会向应用程序通知该事件，直到该事件被处理<br>。
对于ET模式，当epoll_wait检测到其上有事件发生并将此事件通知给应用程序后，应用程序必须立即处理该事件，后续epoll_wait不再通知此事件。<br>
可见ET模式很大程度上降低了同一个epoll事件被触发的次数，因此效率高于LT。[示例代码](https://github.com/CodeDrugger/HPLSP/blob/master/code/etlt.cpp)<br>
### EPOLLONESHOT
一个线程或进程读取完socket上的数据并开始处理时，如果该socket上又有新的数据可读，此时另一个线程或进程被唤醒来读取数据，就会出现两个线程或进程操作同一个socket的局面，为了避免这种情况，可以用epoll的EPOLLONWSHOT解决。
### 三组I/O复用函数的比较
![](https://github.com/CodeDrugger/HPLSP/raw/master/pic/014.png)<br>
### 非阻塞connect
connect默认是阻塞的，在需创建大量线程向另一主机发送数据时，在connect是阻塞的情况下，如果网络发生异常，将有大量线程阻塞在此处等待超时（75s至几分钟），这些线程不会释放系统资源，资源达到上限后导致系统资源枯竭。如果使用非阻塞connect，connect将立即返回，接着调用select或poll等待设定的时间后返回，再调用getsockopt获取并清除socket上的错误信息，如果错误是0，表示调用成功。具体过程如下：
- 创建socket，返回套接口描述符；
- 调用fcntl把套接口描述符设置成非阻塞；
- 调用connect开始建立连接；
- 判断连接是否成功建立:<br>
  - 如果connect返回0，表示连接成功（服务器和客户端在同一台机器上时就有可能发生这种情况）；<br>
  - 调用select来等待连接建立成功完成；<br>
    - 如果select 返回0，则表示建立连接超时。我们返回超时错误给用户，同时关闭连接，以防止三路握手操作继续进行下去。<br>
    - 如果select 返回大于0的值，则需要检查套接口描述符是否可写，如果套接口描述符可写，则我们可以通过调用getsockopt来得到套接口上待处理的错误（SO_ERROR）。如果连接建立成功，这个错误值将是0；如果建立连接时遇到错误，则这个值是连接错误所对应的errno值（比如：ECONNREFUSED,ETIMEDOUT等）。<br>
### 一个端口同时处理TCP和UDP
[示例代码](https://github.com/CodeDrugger/HPLSP/blob/master/code/tcpudp.cpp)<br>
## 八.信号
### Linux信号概述
一个进程向其他进程发送信号的API是kill函数
``` C++
#include <sys/type.h>
#include <signal.h>
/*
pid > 0：信号发送给PID是pid的进程
pid = 0：信号发送给本进程组内的其他进程
pid = -1：信号发送给除init进程之外的所有进程，但需要有权限
pid < -1：信号发送给组ID为-pid的进程组中的所有成员
调用成功返回0，失败返回-1，errno取值：EINVAL（无效信号）、EPERM（没有权限发送信号）、ESRCH（目标进程或进程组不存在）
*/
int kill(pid_t pid, int sig);
```
目标进程在收到一个信号后，需要定义一个接收函数处理之，处理函数的原型为：
``` C++
#include <signal.h>
typedef void (*_sighandler_t) (int);
```
整数类型的参数用来指示信号类型，信号处理函数应该是可重入的，否则容易引起竞态条件。<br>
除了用户定义的信号处理函数，还有其他两种处理方式：
``` C++
#include <bits/signum.h>
#define SIG_DFL ((__sighandler_t) 0)
#define SIG_IGN ((__sighandler_t) 1)
```
SIG_IGN表示忽略目标信号，SIG_DFL表示使用型号的默认处理方式，默认处理方式有结束进程（Term），忽略信号（Ign），结束进程并生成转储文件（Core），暂停进程（Stop），继续进程（Cont）。<br>
如果程序在执行处于阻塞状态的系统调用时收到了信号，并且我们为该信号设置了信号处理函数，则默认情况下系统调用将被中断，errno被置为EINTR，可以使用sigaction函数为信号设置SA_RESTART标志以重启被该型号中断的系统调用。<br>
### 信号函数
要为一个信号设置处理函数，可以使用signal函数调用：
``` C++
#include <signal.h>
/*
sig：指出要捕获的信号类型
_handler：指定信号sig的处理函数
调用成功返回函数指针，该返回值是前一次调用signal传入的函数指针，或者是信号sig对应的默认处理函数指针SIG_DEF，出错返回SIG_ERR。
*/
_sighandler_t signal(int sig, _sighandler_t _handler);
```
更健壮的接口是：
``` C++
#include <signal.h>
/*
sig：指出要捕获的信号类型
act：指定新的信号处理方式
oact：输出信号先前的处理方式（如果不为NULL的话）
成功返回0，失败返回-1
*/
int sigaction(int sig, const struct sigaction* act, struct sigaction* oact);

/*
sa_handler：指定信号处理函数
sa_mask：设置进程的信号掩码（在原有掩码上增加）
sa_flags：设置程序收到信号时的行为，取值见后图
sa_restorer：已过时，勿用
*/
struct sigaction {
    _sighandler_t sa_handler;
    _sigset_t sa_mask;
    int sa_flags;
    void (*sa_restorer) (void);
}
```
![](https://github.com/CodeDrugger/HPLSP/raw/master/pic/015.png)<br>
### 信号集
#### 信号集函数
Linux使用sigset_t表示一组信号，定义如下：
``` C++
#include <bits/sigset.h>
#define _SIGSET_NWORDS (1024 / (8 * sizeof(unsigned long int)))
typedef struct {
    unsigned long int __val[_SIGSET_NWORDS];
} __sigset_t;
```
sigset_t其实是一个长整型数组，数组的每个元素的每一位表示一个信号，定义方式与fd_set类似，Linux提供了一组函数来设置、修改、删除、查询信号集：
``` C++
#include <signal.h>
int sigemptyset(sigset_t* _set); //清空信号集
int sigfillset(sigset_t* _set); // 设置信号集中的所有信号
int sigaddset(sigset_t* _set, int _signo); //将信号signo添加到信号集中
int sigdelset(sigset_t* _set, int _signo); //将信号signo从信号集中删除
int sigismember(sigset_t* _set, int _signo); //测试信号signo是否在信号集中
```
#### 进程信号掩码
可以利用sigaction结构体的sa_mask成员来设置进程的信号掩码，也可以使用如下函数设置：
``` C++
/*
_how：指定设置进程掩码的方式，取值为SIG_BLOCK（新掩码是现有掩码和_set的并集）、SIG_UNBLOCK（设置后_set将不被屏蔽）、SIG_SETMASK（设置为_set）
_set：新的信号掩码
_oset：原信号掩码，如果不为NULL的话
成功返回0，失败返回-1
*/
int sigprocmask(int _how, _const sigset_t* _set, sigset_t* _oset);
```
#### 被挂起的信号
设置进程掩码后，被屏蔽的信号将不能被进程接收，如果给进程发送一个被屏蔽的信号，则操作系统将该信号设置为进程的一个被挂起的信号，如果对被挂起的信号取消屏蔽，则它能立即被进程接收到，如下函数能获取进程当前被挂起的信号：
``` C++
#include <signal.h>
/*
set：用于保存被挂起的信号集
成功返回0，失败返回-1
*/
int sigpending(sigset_t* set);
```
进程多次接收到同一个被挂起的信号，sigpending也只能反映一次，并且修改掩码也只能使该信号被触发一次
### 统一事件源
信号是一种异步事件，信号的处理程序和程序主循环是两条路线，信号的处理函数需要尽可能快地执行完毕，以确保该信号不会被屏蔽太久，一种典型的处理方案是，把信号的主要处理逻辑放在主循环中，当信号处理函数被触发时，它只是简单地通知主循环接收到信号，并把信号值传递给主循环，主循环再根据信号值执行目标信号对应的逻辑代码。<br>
主循环通常用管道传递信号值，信号处理函数往管道的写端写入信号值，主循环从读端读取信号值。[示例代码](https://github.com/CodeDrugger/HPLSP/blob/master/code/unievent.cpp)<br>
### 网络编程相关信号
#### SIGHUP
SIGHUP信号在用户终端连接(正常或非正常)结束时发出，通常是在终端的控制进程结束时，通知同一session内的各个作业，这时它们与控制终端不再关联。系统对SIGHUP信号的默认处理是终止收到该信号的进程。所以若程序中没有捕捉该信号，当收到该信号时，进程就会退出。<br>
SIGHUP会在以下3种情况下被发送给相应的进程：
- 终端关闭时，该信号被发送到session首进程以及作为job提交的进程（即用&符号提交的进程，后台运行的）；
- session首进程退出时，该信号被发送到该session中的前台进程组中的每一个进程；
- 若父进程退出导致进程组成为孤儿进程组，且该进程组中有进程处于停止状态（收到SIGSTOP或SIGTSTP信号），该信号会被发送到该进程组中的每一个进程。<br>
通常使用SIGHUP重读配置文件。
#### SIGPIPE
往一个关闭的管道或socket连接中写数据将引发SIGPIPE信号，我们需要在程序里捕获并处理该信号，或者至少是忽略它，因为该信号的默认行为是结束进程。引起SIGPIPE的写操作将设置errno为EPIPE。<br>
send函数的MSG_NOSIGNAL标志可以禁止触发SIGPIPE信号。
#### SIGURG
内核通知应用程序带外数据到达主要有两种方法，一种是是I/O复用中报告给应用程序的异常事件，另一种就是SIGURG信号。
## 定时器
alarm函数用来在一段时间后向当前进程发送SIGALRM信号
``` C++
#include <unistd.h>
unsigned int alarm(unsigned int seconds);
```
## 多进程编程
### fork系统调用
``` C++
#include <sys/types.h>
#include <unistd.h>
pid_t fork(void);
```
该函数的每次调用都返回2次，在父进程中返回的是子进程的PID，子进程中返回0，调用失败返回-1。<br>
fork复制当前进程，在内核进程表中创建一个新的进程项，指针、标志寄存器等都与原进程相同，进程的PPID被赋值为原进程的PID，信号位图被清除；父子进程的代码完全相同，子进程还会复制数据（堆数据，栈数据，静态数据），数据的复制采用写时复制，任一进程对数据执行了写操作时，复制才会发生（首先发生缺页中断，然后操作系统给子进程分配内存复制父进程的数据），创建子进程后，父进程中打开的文件描述符默认在子进程中也是打开的，文件描述符引用计数加1，父进程的用户根目录，当前工作目录等变量的引用计数也会加1。<br>
### exec系列系统调用
有时我们需要在子进程中执行其他程序，即替换当前进程映像，需要使用exec系列函数：
``` C++
#include <unistd.h>
extern char** environ;

/*
path：指定可执行文件的完整路径
file：接受文件名，该文件的具体位置则在环境变量PATH中搜寻
arg：接受可变参数
argv：接受参数数组
arg和argv都会被传递给新程序（path或file指定的程序）的main函数
envp：用于设置新程序的环境变量，如果未设置，将使用全局变量environ指定的环境变量
*/
int execl(const char* path, const char* arg, ...);
int execlp(const char* file, const char* arg, ...);
int execle(const char* path, const char* arg, ..., char* const envp[]);
int execv(const char* path, const char* arg[]);
int execvp(const char* file, const char* arg[]);
int execve(const char* path, const char* arg[], char* const envp[]);
```
通常exec系列函数是不返回的，除非出错，出错时返回-1，如果没出错，exec系列函数之后的代码都会再执行，因为此时原程序已经被exec指定的程序完全替换（包括代码和数据）。exec不会关闭原程序打开的文件描述符，除非该文件描述符设置了类似SOCK_CLOEXEC的属性。
### 处理僵尸进程
对于多进程程序，父进程一般需要跟踪子进程的退出状态，所以子进程结束运行时，内核不会立即释放该进程的进程表表项，以满足父进程对该子进程退出信息的查询。<br>
子进程结束运行之后，父进程读取其退出状态之前，我们称该子进程处于僵尸态，另一种使进程进入僵尸态的情况是，父进程结束或异常终止，而子进程还在继续运行，此时子进程的PPID将被置为1，即init进程，init进程接管了该子进程，并等待他结束，在父进程退出后，子进程退出之前，该子进程处于僵尸态。<br>
无论哪种情况，如果父进程没有正确地处理子进程的返回信息，子进程都将停留在僵尸态，并占据内核资源，这是不能容许的，因为内核资源有限。下面这对系统调用在父进程中调用，以等待子进程的结束，并获取子进程信息，从而避免僵尸进程的产生，或者使子进程的僵尸态立即结束。
``` C++
#include <sys/types.h>
#include <sys/wait.h>
pid_t wait(int* stat_loc);
pid_t waitpid(pid_t pid, int* stat_loc, int options);
```
wait函数将阻塞进程，直到该进程的某个子进程结束运行为止，它返回结束运行的子进程的PID，并将该子进程的的退出信息存储于stct_loc指向的内存中，可以使用下列宏来解析子进程退出的状态：
![](https://github.com/CodeDrugger/HPLSP/raw/master/pic/016.png)<br>
wait函数的阻塞特性显然不是服务器程序所希望的，而waitpid解决了这个问题，waitpid只能等待由pid参数指定的子进程，如果pid取值为-1，那么它就和wait函数一样，即等待任意一个子进程结束，stat_loc参数的含义与wait函数的stat_loc相同，options可以控制waitpid函数的行为，该参数最常用的取值是WNOHANG，取该值是，waitpid调用将是非阻塞的：如果pid指定的目标子进程还没有结束或意外终止，则waitpid立即返回0，如果目标子进程正常退出了，返回子进程的PID，调用失败返回-1。
在事件已经发生的情况下执行非阻塞调用才能提高程序效率，对于waitpid函数而言，我们最好在某个子进程退出之后再调用它，可以使用SIGCHLD信号判断，当一个进程结束时，他将给其父进程发送一个SIGCHLD信号，我们可以在父进程中捕获SIGCHLD信号，并在信号处理函数中调用waitpid彻底结束一个子进程。
### 管道
管道能在父子进程之间传递数据，利用的是fork调用之后两个管道文件描述符都保持打开，一对这样的文件描述符只能保证父、子进程之间一个方向的数据传输，父进程和子进程必须一个关闭fd[0]，一个关闭fd[1]，如果要实现双向传输，就必须使用两个管道，或者使用socketpair。
### 信号量
#### 信号量原语
信号量由Dijkstra提出，是一种特殊的变量，它只能取自然数值并支持两种操作，P（进入临界区，占用资源）、V（退出临界区，释放资源），含义如下：<br>
- P(SV)，如果SV的值大于0，就将它减一；如果SV的值等于0，则挂起进程；
- V(SV)，如果有其他进程因为等待SV进程而挂起，则唤醒之，如果没有就将SV加1；

信号量的取值可以是任何自然数，最常用的是取值为0、1的二进制信号量，任何高级语言都不能模拟信号量，因为都没有一个原子操作可以同时完成如下两步操作：检测变量是否为0/1，如果是再将它置为1/0<br>
#### semget系统调用
semget系统调用创建一个新的信号量集，或者获取一个已经存在的信号量集，定义如下：
``` C++
#include <sys/sem.h>
/*
key：用来标识一个全局唯一的信号量集
num_sems：指定要创建/获取的信号量集中信号量的数目，创建时必须指定，获取时可以设置为0
sem_flags：指定一组标志，格式与含义都和open的mode参数相同
调用成功返回正整数，是信号量集的标识符，失败返回-1
*/
int semget(ket_t key, int num_sems, int sem_flags);
```
#### semop系统调用
改变信号量的值，即P、V操作，定义如下：
``` C++
#include <sys/sem.h>
/*
sem_id：semget返回的信号量集标识符
sem_ops：sembuf定义见后文
num_sem_ops：指定要执行的操作个数，即sem_ops数组中元素的个数
调用成功返回0，失败返回-1，失败时sem_ops中所有的操作都不会被执行
*/
int semop(int sem_id, struct sembuf* sem_ops, size_t num_sem_ops);

struct sembuf {
unsigned short int sem_num;
short int sem_op;
short int sem_flg;
}
```
sem_num是信号量集中信号的编号，从0开始；<br>
sem_op指定操作类型，其可选值为正整数、0、负整数，操作行为又受sem_flg的影响，sem_flg可选值有IPC_NOWAIT（无论是否操作成功，立即返回）、SEM_UNDO（当进程退出时取消操作）。具体行为如下：
- 如果sem_op大于0，semop将被操作的信号量的值加sem_op，该操作要求进程对信号量有写权限，
