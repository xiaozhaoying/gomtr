package tools

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"github.com/PuerkitoBio/goquery"
	"github.com/axgle/mahonia"
)

type winsize struct {
	rows    uint16
	cols    uint16
	xpixels uint16
	ypixels uint16
}

var (
	IPInfo = make(map[string]string, 32)
	urlMap = map[string]string{
		"taobao":  "http://ip.taobao.com/service/getIpInfo.php?ip=%s",
		"jinrong": "http://www.030904.com/IP/Address.asp?Action=Query",
		"ipcn":    "https://www.ip.cn/index.php?ip=%s",
	}
	mu          sync.RWMutex
	ErrIPParse  = errors.New("ip解析失败")
	ErrNODevice = errors.New("没找到任何网卡")
	ErrGetTerm  = errors.New("获取tty属性失败")
	ErrSetTerm  = errors.New("设置tty属性失败")
)

func StrinigToList(str string) [DATA_LEN]byte {
	var (
		length = len(str)
		res    [DATA_LEN]byte
	)
	for i := 0; i < length && i < DATA_LEN; i++ {
		res[i] = str[i]
	}
	return res
}

// 返回ip信息，不会阻塞进程，没有在map中找到即返回""空字符串
// 没有的会新生成goroutine执行获取
func MapIPInfo(ip string) string {
	if res, ok := IPInfo[ip]; ok {
		return res
	}
	go func(ip string) {
		if FromTaoBao(ip) || FromIPCN(ip) || FromJinRong(ip) {
			return
		}
	}(ip)
	return "***"
}

// 从淘宝地址库获取IP地址
func FromTaoBao(ip string) bool {
	var (
		resp *http.Response
		err  error
		s    struct {
			Code int
			Data struct {
				IP, Country, Region, City, ISP string
			}
		}
	)
	if resp, err = http.Get(fmt.Sprintf(urlMap["taobao"], ip)); err != nil {
		return false
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)

	if err = json.Unmarshal(body, &s); err != nil {
		return false
	}
	if s.Code != 0 {
		return false
	}
	mu.Lock()
	IPInfo[ip] = fmt.Sprintf("%s%s%s%s(Taobao)", s.Data.Country, s.Data.Region, s.Data.City, s.Data.ISP)
	mu.Unlock()
	return true
}

// 从ipcn获取IP地址信息
func FromIPCN(ip string) bool {
	var (
		req  *http.Request
		resp *http.Response
		err  error
		doc  *goquery.Document
		cli  = &http.Client{}
		res  string
	)
	req, _ = http.NewRequest("GET", fmt.Sprintf(urlMap["ipcn"], ip), nil)
	req.Header.Add("referer", "https://www.ip.cn/index.php")
	req.Header.Add("user-agent", "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.106 Safari/537.36")

	if resp, err = cli.Do(req); err != nil {
		return false
	}
	defer resp.Body.Close()

	doc, _ = goquery.NewDocumentFromReader(resp.Body)
	res = doc.Find("#result .well p code").Last().Text()
	if len(res) == 0 {
		return false
	}
	res = strings.Trim(strings.Replace(res, " ", "", -1), `"`)
	mu.Lock()
	IPInfo[ip] = fmt.Sprintf("%s(IPCN)", res)
	mu.Unlock()
	return true
}

// 从030904网站获取信息
func FromJinRong(ip string) bool {
	var (
		err        error
		resp       *http.Response
		buffString *strings.Reader
		doc        *goquery.Document
	)
	if resp, err = http.PostForm(urlMap["jinrong"], url.Values{"ip": {ip}}); err != nil {
		return false
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	buffString = strings.NewReader(mahonia.NewDecoder("gbk").ConvertString(string(body)))
	doc, _ = goquery.NewDocumentFromReader(buffString)
	tmp := doc.Find(".f16").Last().Text()
	if len(tmp) == 0 {
		return false
	}
	mu.Lock()
	IPInfo[ip] = fmt.Sprintf("%s(030904)", strings.Split(tmp, " ")[1])
	mu.Unlock()
	return true
}

func GetAddr() ([4]byte, error) {
	var (
		addr [4]byte
		ip   net.IP
	)
	addrList, err := net.InterfaceAddrs()
	if err != nil {
		return addr, ErrNODevice
	}
	for _, v := range addrList {
		interf, ok := v.(*net.IPNet)
		if !ok {
			continue
		}
		ip = interf.IP
		// 去掉回环地址和ipv6
		if !ip.IsLoopback() && (len(ip.To4()) == net.IPv4len) {
			copy(addr[:], ip.To4())
			return addr, nil
		}
	}
	return addr, ErrNODevice
}

func ParseStringToIP(str string) ([4]byte, string, error) {
	var res [4]byte
	if dest := net.ParseIP(str); dest != nil {
		copy(res[:], dest.To4())
		return res, dest.String(), nil
	}
	if dest, err := net.ResolveIPAddr("ip4", str); err == nil {
		copy(res[:], dest.IP.To4())
		return res, dest.String(), nil
	}
	return res, "", ErrIPParse
}

func DecodeDest(dest *syscall.SockaddrInet4) string {
	var res = make([]string, 4)
	for k, v := range dest.Addr {
		res[k] = strconv.FormatUint(uint64(v), 10)
	}
	return strings.Join(res, ".")
}

// 获取term尺寸
func GetTermSize(fd *os.File) (int, int) {
	var sz winsize
	syscall.Syscall(syscall.SYS_IOCTL,
		fd.Fd(), uintptr(syscall.TIOCGWINSZ), uintptr(unsafe.Pointer(&sz)))
	return int(sz.cols), int(sz.rows)
}

// 获取属性
func GetTermAttr(fd *os.File) (*syscall.Termios, error) {
	var tc = &syscall.Termios{}
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd.Fd(), uintptr(syscall.TCGETS), uintptr(unsafe.Pointer(tc)))
	if errno != 0 {
		return nil, ErrGetTerm
	}
	return tc, nil
}

func SetTermAttr(fd *os.File, tc *syscall.Termios) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd.Fd(), uintptr(syscall.TCSETS), uintptr(unsafe.Pointer(tc)))
	if errno != 0 {
		return ErrSetTerm
	}
	return nil
}
