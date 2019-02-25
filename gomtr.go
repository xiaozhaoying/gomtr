package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"./tools"
	//	"github.com/xiaozhaoying/gomtr/tools"
)

const (
	VERSION_HEADER  = "goMTR [v0.2.1]"
	ICMP_TYPE       = 8
	DEFAULT_PORT    = 33434
	ICMP_HEADER_LEN = 8
)

var (
	PID           uint16              // 进程pid
	BeginSeq      uint16              // 最开始序列号，不变
	CurrentSeq    uint16              // 当前的序列号
	MaxSeq        uint16              = 65535
	MaxSeqCount                       = 0
	SendCount     float32             // 统计已经执行sendPacket多少次
	MaxTTL        = 30                // 最高跳数
	LastTTL       int                 // 上次TTL
	ValidTTL      int                 // 有效TTL
	TmpTTL        = [2]int{0, MaxTTL} // 临时存放的TTL，初始化为[0, MAX_TTL]
	AcceptLoss    = 4                 // 最多接受的丢失的TTL
	TimeOut       = time.Second       // 显示结果的超时时间
	PacketARR     []*Packet           // 发送数据包数组
	CollectARR    []*PacketCollect
	Flush         []*FlushString // 临时存储,只存储有变化的数据
	TTY           *os.File
	OLDTTY        *syscall.Termios
	LWidth, LHigh int                                       // 保存前一次TTY的宽和高
	SpaceList     [256 * 128]byte                           // 空格字符数组
	SpacePos                      = 36                      // 定位时的位置
	LinePos                       = 29                      // Line输出时的位置
	ExitSignal                    = make(chan os.Signal, 1) // 退出信号
	LimitInterval                 = time.Millisecond * 45   // 35
	Debug         bool            = false                   // 调试模式
)

var (
	ErrNoArgs = errors.New("参数有误, 输入IP/域名")
)

type Packet struct {
	TTL        int
	ICMPType   uint8 // 接收的icmp包
	ICMPCode   uint8
	Identifier uint16 // 与pid对比，判断是否有效
	Seq        uint16 // 包序列号
	Valid      bool   // 是否有效，统计次数不一样
	Dest       string

	Send time.Time // 数据包发送时间
	Recv time.Time // 接收时间
}

// 统计所有数据包
type PacketCollect struct {
	LossCount   float32 // 丢失次数
	LossPercent float32 // 丢失率
	LastScore   int64   // 上次成绩
	ValidScore  int64   // 总有效时间
	AvgScore    int64   // 平均成绩 = 总有效时间/总有效次数
	BestScore   int64   // 最好时间
	WorstScore  int64   // 最差时间
	Dest        string  // 目的ip
	Line        string  // 线路
}

// 保存Dest地址和Line线路，用于是否刷新输出
type FlushString struct {
	BestScore  int64   // 最好时间
	WorstScore int64   // 最差时间
	AvgScore   float64 // 只保留1位小数点
	Dest       string  // 目的ip
	Line       string  // 线路
}

var (
	SendSock, RecvSock int // 发送和监控句柄
	DestString         string
	RawString          string // 目的地址的原始字符串
	Remote             *syscall.SockaddrInet4
	WorstUse           time.Duration // 保存最差用时
)

func init() {
	var (
		localHost = [4]byte{0, 0, 0, 0} // 源地址
		destHost  [4]byte
		err       error
	)
	// 参数
	if len(os.Args) != 2 {
		fmt.Println(ErrNoArgs.Error())
		os.Exit(-1)
	}
	RawString = os.Args[1]
	if destHost, DestString, err = tools.ParseStringToIP(RawString); err != nil {
		fmt.Println(err.Error())
		os.Exit(-1)
	}
	Remote = &syscall.SockaddrInet4{Port: DEFAULT_PORT, Addr: destHost}

	// 构造recv-socket
	RecvSock, _ = syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err = syscall.Bind(RecvSock, &syscall.SockaddrInet4{Port: DEFAULT_PORT, Addr: localHost}); err != nil {
		fmt.Println("绑定端口时出错: ", err)
		os.Exit(-1)
	}
	// 构造send-socket
	SendSock, _ = syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	syscall.Bind(SendSock, &syscall.SockaddrInet4{Port: DEFAULT_PORT, Addr: localHost})
	syscall.SetNonblock(SendSock, true)

	// 初始化MaxTTL
	if ttl := os.Getenv("TTL"); len(ttl) != 0 {
		if t, err := strconv.Atoi(ttl); err == nil && t > 1 && t < 32 { // TTL限定在1-32之间
			MaxTTL = t
			TmpTTL[1] = MaxTTL
		}
	}

	rand.Seed(time.Now().UnixNano())
	BeginSeq = uint16(rand.Intn(1<<11) * MaxTTL) // 保证BeginSeq是TTL的整数倍
	CurrentSeq = BeginSeq
	PID = uint16(syscall.Getpid())

	PacketARR = make([]*Packet, MaxTTL)
	CollectARR = make([]*PacketCollect, MaxTTL)
	Flush = make([]*FlushString, MaxTTL)
	for i := 0; i < MaxTTL; i++ {
		PacketARR[i] = &Packet{}
		CollectARR[i] = &PacketCollect{}
		Flush[i] = &FlushString{}
	}
	for i := 0; i < 256*128; i++ {
		SpaceList[i] = ' '
	}

	// TTY设置
	TTY, _ = os.OpenFile("/dev/tty", syscall.O_RDWR, 0666)
	if OLDTTY, err = tools.GetTermAttr(TTY); err != nil {
		fmt.Println(err.Error())
		os.Exit(-1)
	}
	tc := *OLDTTY
	tc.Lflag ^= syscall.ECHO
	if err = tools.SetTermAttr(TTY, &tc); err != nil {
		fmt.Println(err.Error())
		os.Exit(-1)
	}

	// debug信息
	if debug := os.Getenv("DEBUG"); debug == "1" {
		Debug = true
	}
	signal.Notify(ExitSignal, syscall.SIGINT) // 退出信号
	go exit()
}

func main() {
	defer func() {
		tools.SetTermAttr(TTY, OLDTTY)
		TTY.Close()
	}()
	var (
		buff         = make([]byte, 128)
		timeAfter    <-chan time.Time
		dest         string // 返回的IP地址
		p            *syscall.SockaddrInet4
		timeout      syscall.Timeval
		nextEcho     time.Time     // 下一次显示输出的时间
		collectUse   time.Duration // collect函数使用时间
		left         time.Duration // 剩余给发送数据和接收数据的时间
		collectStart time.Time
		err          error
		addr         syscall.Sockaddr
		icmp         = &tools.ICMP{
			Type:       ICMP_TYPE,
			Code:       0,
			Checksum:   0,
			Identifier: PID,
			Data:       [tools.DATA_LEN]byte{'A', 'B', 'C', 'D'}}
	)

	OutPut(collectUse, left)
	nextEcho = time.Now().Add(TimeOut)
	timeAfter = time.After(nextEcho.Sub(time.Now()))
	for {
		SendPacket(icmp, Remote)
		for {
			// 接收相关
			timeout = syscall.NsecToTimeval((nextEcho.Sub(time.Now())).Nanoseconds())
			if err = syscall.SetsockoptTimeval(RecvSock, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &timeout); err != nil { // 重置超时
				break
			}
			if _, addr, err = syscall.Recvfrom(RecvSock, buff, 0); err != nil {
				break
			}
			p = addr.(*syscall.SockaddrInet4)
			dest = tools.DecodeDest(p)
			DecodePacket(dest, buff)
		}
		collectStart = time.Now()
		Collect() // 整理数据
		<-timeAfter
		OutPut(collectUse, left) // 输出数据

		collectUse = time.Since(collectStart) // 从Collect到OutPut一共用时
		left = TimeOut - collectUse
		if left > WorstUse {
			nextEcho = time.Now().Add(left)
		} else {
			TimeOut = TimeOut * 5 / 4
			nextEcho = time.Now().Add(TimeOut - collectUse)
		}
		timeAfter = time.After(nextEcho.Sub(time.Now())) // 重置，下一次输出显示的时间
	}
}

// 打印输出
func OutPut(use, left time.Duration) {
	var (
		line        int // 行数
		last        float32
		avg, avgabs float64 // avg平均数的误差
		best, wrst  float32
		change      bool = false // 显示器w/h是否改变
		p           *PacketCollect
		f           *FlushString
	)
	defer func() {
		if err := recover(); err != nil {
			fmt.Println(err)
			tools.SetTermAttr(TTY, OLDTTY)
			_, height := tools.GetTermSize(TTY)
			fmt.Printf("\033[?25h\033[%d;0H", height)
			os.Exit(-1)
		}
	}()
	width, height := tools.GetTermSize(TTY)
	if LWidth != width || LHigh != height {
		head(width, height)
		fmt.Printf("\033[2;%dH%9s", width-24, time.Now().Format("Mon Jan 2 15:04:05 2006"))
		change = true
	}
	// 确定有效ttl
	if TmpTTL[0] == 0 {
		return
	}
	if TmpTTL[1] == MaxTTL || TmpTTL[1]-TmpTTL[0] >= AcceptLoss || TmpTTL[0] >= TmpTTL[1] {
		ValidTTL = TmpTTL[0] + 1
	} else {
		ValidTTL = TmpTTL[1]
	}

	if Debug {
		fmt.Printf("\033[3;%dH\033[4mDebug: timeout: %+v, use: %5.1fms, left: %5.1fms, worst: %5.1fms\033[0m",
			LinePos, TimeOut, float64(use)/1000/1000, float64(left)/1000/1000, float64(WorstUse)/1000/1000) // 调试信息
	}
	// 输出当前时间
	fmt.Printf("\033[2;%dH%9s", width-24, time.Now().Format("Mon Jan 2 15:04:05 2006"))

	// 输出
	for i := 0; i < ValidTTL; i++ {
		line = i + 5
		p = CollectARR[i]
		f = Flush[i]

		if p.Dest == "" { // 没有收到响应包
			fmt.Printf("\033[%d;0H%2d. %-24s\n", line, i+1, "???")
			continue
		}
		last = float32(p.LastScore) / 1000 / 1000
		avg = float64(p.AvgScore) / 1000 / 1000
		avgabs = f.AvgScore - avg
		f.AvgScore = avg // 设置成新的avg
		best = float32(p.BestScore) / 1000 / 1000
		wrst = float32(p.WorstScore) / 1000 / 1000
		if change {
			fmt.Printf("\033[%d;0H%2d. %-24s%-32s\033[K\033[%d;%dH%6.1f%%%6.0f%6.1f%6.1f%6.1f%6.1f \n",
				line, i+1, p.Dest, p.Line, line, width-SpacePos-1, p.LossPercent, SendCount, last, avg, best, wrst)
			time.Sleep(LimitInterval) // 显示更加顺滑
			continue
		}
		if len(f.Dest) != 0 {
			fmt.Printf("\033[%d;0H%2d. %-24s", line, i+1, f.Dest)
			f.Dest = ""
		}
		if len(f.Line) != 0 {
			fmt.Printf("\033[%d;%dH%-32s", line, LinePos, f.Line)
			f.Line = ""
		}
		fmt.Printf("\033[%d;%dH%6.1f%%%6.0f%6.1f", line, width-SpacePos-1, p.LossPercent, SendCount, last)
		if math.Abs(avgabs) >= 0.1 { // 误差在0.1之内忽略
			fmt.Printf("\033[%d;%dH%6.1f", line, width-18, avg)
		}
		if f.BestScore != 0 {
			fmt.Printf("\033[%d;%dH%6.1f", line, width-12, best)
			f.BestScore = 0
		}
		if f.WorstScore != 0 {
			fmt.Printf("\033[%d;%dH%6.1f", line, width-6, wrst)
			f.WorstScore = 0
		}
		time.Sleep(LimitInterval) // 显示更加顺滑
	}
	// TTL变化时，清理最后几行
	if ValidTTL < LastTTL {
		fmt.Printf("\033[%d;0H%s", ValidTTL+5, SpaceList[:width*(MaxTTL-ValidTTL)])
	}
	LastTTL = ValidTTL
	LWidth, LHigh = width, height
	// WorstUse = 0 // 降低20%
}

// 统计所有数据
func Collect() {
	var (
		interval int64
		ttl      int
		p        *Packet
		c        *PacketCollect
		f        *FlushString
	)
	if SendCount == 0 {
		return
	}

	for i := 0; i < MaxTTL; i++ {
		ttl = i + 1
		p = PacketARR[i]  // 原始数据包
		c = CollectARR[i] // 统计包
		f = Flush[i]      // 临时存放的，需要输出的数据
		if !p.Valid {
			c.LossCount++
			c.LossPercent = c.LossCount / SendCount * 100
			continue
		}
		interval = p.Recv.Sub(p.Send).Nanoseconds()
		c.LastScore = interval // 上次成绩
		c.ValidScore += interval
		c.AvgScore = c.ValidScore / int64(SendCount-c.LossCount) // 平均数
		c.LossPercent = c.LossCount / SendCount * 100
		if interval < c.BestScore || c.BestScore == 0 {
			c.BestScore, f.BestScore = interval, interval
		}
		if interval > c.WorstScore || c.WorstScore == 0 {
			c.WorstScore, f.WorstScore = interval, interval
		}
		if c.Dest != p.Dest {
			c.Dest, f.Dest = p.Dest, p.Dest
		}
		if len(c.Line) <= 3 {
			c.Line = tools.MapIPInfo(c.Dest)
			if len(c.Line) > 3 {
				f.Line = c.Line
			}
		}
		if interval > WorstUse.Nanoseconds() { // 统计最差时间
			WorstUse = time.Duration(interval)
		}
		p.Valid = false // 处理过置false
		if p.Dest == DestString {
			// 确定有效TTL
			if TmpTTL[1] > ttl {
				TmpTTL[1] = ttl
			} else if TmpTTL[0] > ttl {
				TmpTTL[1] = ttl
			}
			return // 提前退出for循环
		} else {
			if TmpTTL[0] < ttl {
				TmpTTL[0] = ttl
			}
		}
	}
}

// 分析数据包
func DecodePacket(recvIP string, recv []byte) {
	var (
		finICMP  int
		index    int
		p        *Packet
		now      = time.Now()
		recvICMP = &tools.ICMP{} // icmp包
		buff     bytes.Buffer
	)
	// recv为ip层数据包，分析第一个icmp首部
	IPPacketLen := int(recv[0] & 15 * 4)
	ICMPType := recv[IPPacketLen] & 15
	ICMPCode := recv[IPPacketLen] >> 4
	// 超时包
	if ICMPType == 11 && ICMPCode == 0 { // 判断Identifier是否为pid
		finICMP = int(recv[IPPacketLen+ICMP_HEADER_LEN]&15*4) + (IPPacketLen + ICMP_HEADER_LEN) // 第一个icmp包
	} else if ICMPType == 0 && ICMPCode == 0 { // icmp回复包,目的主机回复包
		finICMP = IPPacketLen
	} else {
		return
	}
	buff.Write(recv[finICMP : finICMP+ICMP_HEADER_LEN+tools.DATA_LEN])
	binary.Read(&buff, binary.BigEndian, recvICMP)
	// 过滤其他程序icmp包
	if recvICMP.Identifier != PID {
		return
	}
	// 判读相关的Seq
	if CurrentSeq < recvICMP.Seq {
		index = (int(recvICMP.Seq) + int(MaxSeq)*(MaxSeqCount-1)) % MaxTTL
	} else {
		index = (int(recvICMP.Seq) + int(MaxSeq)*MaxSeqCount) % MaxTTL
	}
	p = PacketARR[index]
	p.Recv = now
	p.ICMPCode = ICMPCode
	p.ICMPType = ICMPType
	p.Dest = recvIP
	p.Valid = true
}

// 发送数据包
func SendPacket(icmp *tools.ICMP, remote *syscall.SockaddrInet4) {
	var (
		buff bytes.Buffer
		p    *Packet
	)
	for i := 1; i <= MaxTTL; i++ {
		syscall.SetsockoptInt(SendSock, 0x0, syscall.IP_TTL, i)
		if CurrentSeq == MaxSeq {
			MaxSeqCount++
		}
		CurrentSeq = CurrentSeq % MaxSeq
		// 初始化icmp结构体
		icmp.Checksum = 0 // 清除上一次的校验码
		icmp.Seq = CurrentSeq
		binary.Write(&buff, binary.BigEndian, icmp)
		icmp.CheckSum(buff.Bytes())
		buff.Reset()

		// 发送icmp数据
		binary.Write(&buff, binary.BigEndian, icmp)
		syscall.Sendto(SendSock, buff.Bytes(), 0, remote)
		buff.Reset()

		// 记录时间
		p = PacketARR[int(CurrentSeq)%MaxTTL]
		p.TTL = i
		p.Identifier = PID
		p.Send = time.Now()
		p.Seq = CurrentSeq
		p.Valid = false
		CurrentSeq++
	}
	SendCount++
}

func head(w, h int) {
	var buf = bytes.Buffer{}

	buf.WriteString(fmt.Sprintf("\033[2J\033[1m\033[1;%dH%s\n", (w-len(VERSION_HEADER))/2, VERSION_HEADER))
	buf.WriteString(fmt.Sprintf("\033[2;0H Dest: \033[0m%s\n", RawString))
	buf.WriteString(fmt.Sprintf(" \033[1mKeys:\033[0m ^C Quit\033[%d;%dH\033[1m%8s%17s\033[0m\n",
		3, w-SpacePos+2, "Packets", "Pings"))
	buf.WriteString(fmt.Sprintf("\033[1;30;47m%-28s%-32s\033[K\033[%d;%dH%6s%6s%6s%6s%6s%6s\033[0m\033[?25l \n",
		" Host", "Line", 4, w-SpacePos, "Loss%", "Snt", "Last", "Avg", "Best", "Wrst"))
	fmt.Printf("%s", buf.String())
}

func exit() {
	<-ExitSignal
	tools.SetTermAttr(TTY, OLDTTY)
	_, height := tools.GetTermSize(TTY)
	fmt.Printf("\033[?25h\033[%d;0H", height)
	os.Exit(0)
}
