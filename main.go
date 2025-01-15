package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

func encrypt(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aesgcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := aesgcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

func decrypt(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aesgcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func sendFile(ip string, port int, path string) {
	conn, err := net.Dial("tcp", ip+":"+strconv.Itoa(port))
	if err != nil {
		fmt.Println("连接服务器失败:", err)
		return
	}
	defer conn.Close()

	absPath, err := filepath.Abs(path)
	if err != nil {
		fmt.Println("获取文件绝对路径失败:", err)
		return
	}

	file, err := os.Open(absPath)
	if err != nil {
		fmt.Println("打开文件失败:", err)
		return
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		fmt.Println("获取文件信息失败:", err)
		return
	}

	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		fmt.Println("生成 AES 密钥失败:", err)
		return
	}

	_, err = conn.Write(key)
	if err != nil {
		fmt.Println("发送Key失败", err)
		return
	}

	fileSize := fileInfo.Size()
	err = binary.Write(conn, binary.BigEndian, fileSize)
	if err != nil {
		fmt.Println("发送FileSize失败:", err)
		return
	}

	fileName := fileInfo.Name()
	fileNameEncryptByte, err := encrypt([]byte(fileName), key)
	if err != nil {
		fmt.Println("加密FileName失败")
		return
	}

	err = binary.Write(conn, binary.BigEndian, int64(len(fileNameEncryptByte)))
	if err != nil {
		fmt.Println("发送FileNameLength失败")
		return
	}

	_, err = conn.Write(fileNameEncryptByte)
	if err != nil {
		fmt.Println("发送FileName失败", err)
		return
	}

	buffer := make([]byte, 1024)
	totalSent := int64(0)
	startTime := time.Now()
	for {
		n, err := file.Read(buffer)
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Println("读取文件失败:", err)
			return
		}

		encryptedData, err := encrypt(buffer[:n], key) // 只加密实际读取的字节
		if err != nil {
			fmt.Println("加密数据失败:", err)
			return
		}
		// println(hex.EncodeToString(encryptedData))
		_, err = conn.Write(encryptedData)
		if err != nil {
			fmt.Println("发送数据失败:", err)
			return
		}
		totalSent += int64(n)
		sentMB := float64(totalSent) / (1024 * 1024)
		totalMB := float64(fileSize) / (1024 * 1024)
		percentage := float64(totalSent) / float64(fileSize) * 100
		elapsed := time.Since(startTime).Seconds()
		speed := sentMB / elapsed
		fmt.Printf("\r发送进度：%.2f%% (%.2fMB/%.2fMB) %.2fMB/s", percentage, sentMB, totalMB, speed)
	}
	fmt.Println()
}

func recvFile(port int) {
	ln, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		fmt.Println("监听端口失败:", err)
		return
	}
	defer ln.Close()

	conn, err := ln.Accept()
	if err != nil {
		fmt.Println("接受连接失败:", err)
		return
	}
	defer conn.Close()

	key := make([]byte, 32)
	_, err = io.ReadFull(conn, key)
	if err != nil {
		fmt.Println("接收Key失败", err)
		return
	}
	// fmt.Printf("Key: %s\n", hex.EncodeToString(key))

	var fileSize int64
	err = binary.Read(conn, binary.BigEndian, &fileSize)
	if err != nil {
		fmt.Println("接收FileSize失败:", err)
		return
	}

	if fileSize == 0 {
		fmt.Println("文件为空，接收结束")
		return
	}

	// fmt.Printf("FileSize: %d\n", fileSize)

	var fileNameLength int64
	err = binary.Read(conn, binary.BigEndian, &fileNameLength)
	if err != nil {
		fmt.Println("接收FileNameLength失败:", err)
		return
	}
	// fmt.Printf("FileNameLength: %d\n", fileNameLength)

	fileNameEncryptByte := make([]byte, fileNameLength)
	_, err = io.ReadFull(conn, fileNameEncryptByte)
	if err != nil {
		fmt.Println("接收FileName失败", err)
		return
	}

	fileNameByte, err := decrypt(fileNameEncryptByte, key)
	fileName := string(fileNameByte)
	if err != nil {
		fmt.Println("解密FileName失败", err)
		return
	}

	// fmt.Printf("FileName: %s\n", fileName)

	file, err := os.Create(fileName)
	if err != nil {
		fmt.Println("创建文件失败:", err)
		return
	}
	defer file.Close()

	totalReceived := int64(0)
	startTime := time.Now()

	for totalReceived < fileSize { // 循环直到接收到所有数据
		buffer := make([]byte, 1024+28) // 缓冲区大小需要包含 GCM 认证标签和Nonce
		n, err := io.ReadFull(conn, buffer)
		if err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break // 文件传输完成或提前结束
			}
		}

		decryptedData, err := decrypt(buffer[:n], key) // 解密实际读取的字节
		if err != nil {
			fmt.Println("AES 解密数据失败:", err)
			fmt.Println("接收到的加密数据:", hex.EncodeToString(buffer[:n])) // 打印接收到的加密数据，用于调试
			return
		}

		written, err := file.Write(decryptedData)
		if err != nil {
			fmt.Println("写入文件失败", err)
			return
		}
		totalReceived += int64(written)
		receivedMB := float64(totalReceived) / (1024 * 1024)
		totalMB := float64(fileSize) / (1024 * 1024)
		percentage := float64(totalReceived) / float64(fileSize) * 100
		elapsed := time.Since(startTime).Seconds()
		speed := receivedMB / elapsed
		fmt.Printf("\r接收进度：%.2f%% (%.2fMB/%.2fMB) %.2fMB/s", percentage, receivedMB, totalMB, speed)
	}
	fmt.Printf("\n%s 传输完成\n", fileName)
}

func getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, addr := range addrs {
		// 检查地址是否是 IP 地址
		ipnet, ok := addr.(*net.IPNet)
		if ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return ""
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("用法: ./transfer send/recv [选项]")
		os.Exit(1)
	}
	mode := os.Args[1]

	ip := flag.String("h", "", "服务器 IP (send 模式需要)")
	port := flag.Int("p", 0, "端口号")
	filename := flag.String("f", "file.txt", "文件名")

	flag.CommandLine.Parse(os.Args[2:])

	if mode == "send" {
		if *ip == "" {
			fmt.Println("发送模式需要指定 IP 地址 (-h)")
			os.Exit(1)
		}
		sendFile(*ip, *port, *filename)
	} else if mode == "recv" {
		listenPort := 0
		if *port == 0 {
			minPort := 30000
			maxPort := 65535
			listenPort = mrand.Intn(maxPort-minPort+1) + minPort
		} else {
			listenPort = *port
		}
		fmt.Printf("监听端口: %d\n", listenPort)
		fmt.Printf("本机IP: %s\n", getLocalIP())
		recvFile(listenPort)
	} else {
		fmt.Println("无效的模式:", mode)
		fmt.Println("请使用 send 或 recv")
		os.Exit(1)
	}
}
