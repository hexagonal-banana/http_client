use std::env;
use std::net::TcpStream;
use std::io::{Read, Write};
use trust_dns_resolver::Resolver;
use trust_dns_resolver::config::*;

fn main() -> Result<(), i32> {
    let args: Vec<String> = env::args().collect();
    
    // 存储各个选项的值
    let mut show_help = false;
    let mut headers: Vec<String> = Vec::new();
    let mut method = String::from("GET");
    let mut data = String::new();
    let mut include_headers = false;
    let mut url = String::new();
    let mut method_specified = false; // 新增：标记是否用户指定了方法
    
    let mut i = 1;
    while i < args.len() {
        let arg = &args[i];
        
        match arg.as_str() {
            "-h" => {
                show_help = true;
            },
            "-H" => {
                if i + 1 < args.len() {
                    headers.push(args[i + 1].clone());
                    i += 1; // 跳过下一个参数，因为它是我们需要的值
                } else {
                    eprintln!("错误: -H 选项需要一个参数");
                    return Err(-1);
                }
            },
            "-X" => {
                if i + 1 < args.len() {
                    method = args[i + 1].clone();
                    method_specified = true; // 标记用户指定了方法
                    i += 1; // 跳过下一个参数
                } else {
                    eprintln!("错误: -X 选项需要一个参数");
                    return Err(-1);
                }
            },
            "-d" => {
                if i + 1 < args.len() {
                    data = args[i + 1].clone();
                    i += 1; // 跳过下一个参数
                } else {
                    eprintln!("错误: -d 选项需要一个参数");
                    return Err(-1);
                }
            },
            "-i" => {
                include_headers = true;
            },
            _ => {
                // 如果参数以-开头但不是我们支持的选项，则报错
                if arg.starts_with("-") {
                    eprintln!("错误: 不支持的选项 '{}'", arg);
                    return Err(-1);
                } else {
                    // 否则认为这是URL
                    url = arg.clone();
                }
            }
        }
        
        i += 1;
    }
    
    // 如果用户提供了数据但没有指定方法，则默认使用POST
    if !data.is_empty() && !method_specified {
        method = String::from("POST");
    }
    
    // 显示帮助信息
    if show_help {
        print_help();
        return Ok(());
    }
    
    // 检查是否提供了URL
    if url.is_empty() {
        eprintln!("错误: 请提供URL");
        print_help();
        return Err(-1);
    }
    
    // 解析URL
    let (host, port, path_query) = match parse_url(&url) {
        Ok(result) => result,
        Err(e) => {
            eprintln!("URL解析错误: {}", e);
            return Err(-1);
        }
    };
    
    // 进行DNS查询获取IP地址
    let ip = match resolve_domain(&host) {
        Ok(ips) => {
            if ips.is_empty() {
                eprintln!("DNS查询未返回任何IP地址");
                return Err(-1);
            }
            ips[0].clone() // 使用第一个IP地址
        }
        Err(e) => {
            eprintln!("DNS查询错误: {}", e);
            return Err(-1);
        }
    };
    
    // 构建并发送HTTP请求
    match send_http_request(&ip, &port, &method, &host, &path_query, &data, &headers, include_headers) {
        Ok(_) => Ok(()),
        Err(e) => {
            eprintln!("HTTP请求错误: {}", e);
            Err(-1)
        }
    }
}

fn parse_url(url: &str) -> Result<(String, String, String), String> {
    // 检查URL是否以http://或https://开头
    let url_without_protocol = if url.starts_with("http://") {
        &url[7..]
    } else if url.starts_with("https://") {
        &url[8..]
    } else {
        return Err("URL必须以http://或https://开头".to_string());
    };
    
    // 查找第一个'#'的位置，用来移除fragment部分
    let url_without_fragment = if let Some(hash_pos) = url_without_protocol.find('#') {
        &url_without_protocol[..hash_pos]
    } else {
        url_without_protocol
    };
    
    // 查找第一个'/'的位置，用来分离主机部分和路径部分
    let (host_port, path_query) = if let Some(slash_pos) = url_without_fragment.find('/') {
        (&url_without_fragment[..slash_pos], &url_without_fragment[slash_pos..])
    } else {
        // 如果没有路径部分，则整个剩余部分都是主机部分
        (url_without_fragment, "/")
    };
    
    // 解析主机和端口
    let (host, port) = if let Some(colon_pos) = host_port.find(':') {
        let host = &host_port[..colon_pos];
        let port = &host_port[colon_pos+1..];
        // 验证端口是否为数字
        if port.parse::<u16>().is_err() {
            return Err("端口必须是有效的数字".to_string());
        }
        (host.to_string(), port.to_string())
    } else {
        // 没有指定端口，根据协议设置默认端口
        let port = if url.starts_with("https://") { "443" } else { "80" };
        (host_port.to_string(), port.to_string())
    };
    
    Ok((host, port, path_query.to_string()))
}

fn resolve_domain(domain: &str) -> Result<Vec<String>, String> {
    // 创建DNS解析器
    let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default())
        .map_err(|e| format!("无法创建DNS解析器: {}", e))?;
    
    // 解析域名
    let response = resolver.lookup_ip(domain)
        .map_err(|e| format!("无法解析域名 '{}': {}", domain, e))?;
    
    // 提取IP地址
    let mut ips = Vec::new();
    for ip in response.iter() {
        ips.push(ip.to_string());
    }
    
    Ok(ips)
}

fn send_http_request(
    ip: &str,
    port: &str,
    method: &str,
    host: &str,
    path_query: &str,
    data: &str,
    headers: &[String],
    include_headers: bool,
) -> Result<(), String> {
    // 建立TCP连接
    let address = format!("{}:{}", ip, port);
    eprintln!("正在连接到: {}", address); // 添加调试日志
    let mut stream = TcpStream::connect(&address)
        .map_err(|e| format!("无法连接到 {}: {}", address, e))?;
    eprintln!("已成功连接到: {}", address); // 添加调试日志
    
    // 构建HTTP请求
    let mut request = format!("{} {} HTTP/1.1\r\n", method, path_query);
    
    // 根据端口号决定Host头的格式
    let host_header = if port == "80" || port == "443" {
        host.to_string()
    } else {
        format!("{}:{}", host, port)
    };
    request.push_str(&format!("Host: {}\r\n", host_header));
    
    // 添加User-Agent头
    request.push_str("User-Agent: curl/1.0\r\n");
    request.push_str("Accept: */*\r\n");    
    
    // 添加自定义请求头
    for header in headers {
        request.push_str(&format!("{}\r\n", header));
    }
    
    // 如果有请求体，添加Content-Length头
    if !data.is_empty() {
        request.push_str(&format!("Content-Length: {}\r\n", data.len()));
    }
    
    // 添加空行结束请求头
    request.push_str("\r\n");
    
    // 如果有请求体，添加请求体
    if !data.is_empty() {
        request.push_str(data);
    }
    
    // 打印将要发送的完整请求
    eprint!("即将发送请求:\n{}", request); // 添加调试日志
    
    // 发送请求
    stream.write_all(request.as_bytes())
        .map_err(|e| format!("发送请求失败: {}", e))?;
    eprintln!("请求已发送"); // 添加调试日志
    
    // 读取响应头
    let mut response_header = String::new();
    let mut buffer = [0; 1];
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => break, // 连接关闭
            Ok(_) => {
                response_header.push(buffer[0] as char);
                // 检查是否读取到响应头结束标记
                if response_header.ends_with("\r\n\r\n") {
                    break;
                }
            }
            Err(e) => return Err(format!("读取响应头失败: {}", e)),
        }
    }
    eprintln!("已接收到响应头，长度: {} 字节", response_header.len()); // 添加调试日志
    
    // 解析Content-Length
    let content_length = parse_content_length(&response_header);
    eprintln!("解析到Content-Length: {:?}", content_length); // 添加调试日志
    
    // 读取响应体
    let mut response_body = Vec::new();
    if let Some(length) = content_length {
        response_body.resize(length, 0);
        let mut total_read = 0;
        while total_read < length {
            match stream.read(&mut response_body[total_read..]) {
                Ok(0) => break, // 连接关闭
                Ok(n) => total_read += n,
                Err(e) => return Err(format!("读取响应体失败: {}", e)),
            }
        }
        eprintln!("已接收到响应体，长度: {} 字节", total_read); // 添加调试日志
    } else {
        // 如果没有Content-Length，使用read_to_end（作为后备方案）
        eprintln!("未找到Content-Length，使用read_to_end读取剩余数据"); // 添加调试日志
        stream.read_to_end(&mut response_body)
            .map_err(|e| format!("读取响应体失败: {}", e))?;
        eprintln!("已接收到响应体，长度: {} 字节", response_body.len()); // 添加调试日志
    }
    
    // 组合响应头和响应体
    let mut response = response_header.into_bytes();
    response.extend_from_slice(&response_body);
    let response_str = String::from_utf8_lossy(&response);
    
    // 分离响应头和响应体
    if include_headers {
        // 输出完整的响应（包括响应头）
        print!("{}", response_str);
    } else {
        // 只输出响应体
        if let Some(pos) = response_str.find("\r\n\r\n") {
            let body = &response_str[pos + 4..];
            print!("{}", body);
        } else {
            // 如果没有找到响应头和响应体的分隔符，输出整个响应
            print!("{}", response_str);
        }
    }
    
    Ok(())
}

// 解析响应头中的Content-Length字段
fn parse_content_length(headers: &str) -> Option<usize> {
    for line in headers.lines() {
        if line.to_lowercase().starts_with("content-length:") {
            if let Some(value) = line.split(':').nth(1) {
                if let Ok(length) = value.trim().parse::<usize>() {
                    return Some(length);
                }
            }
        }
    }
    None
}

fn print_help() {
    println!("用法: hello_world [选项] <URL>");
    println!("");
    println!("选项:");
    println!("  -h        显示帮助信息");
    println!("  -H <header> 添加自定义请求头");
    println!("  -X <method> 指定请求方法 (默认: GET)");
    println!("  -d <data>   发送指定数据");
    println!("  -i        包含响应头信息");
    println!("");
    println!("URL格式: http://host[:port]/path[?query][#fragment]");
}