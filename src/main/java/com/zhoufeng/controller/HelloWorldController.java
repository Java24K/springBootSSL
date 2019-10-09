package com.zhoufeng.controller;

import javax.servlet.http.HttpServletRequest;

import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import com.zhoufeng.utils.BASE64Decode;

@RestController
public class HelloWorldController {
	
    @RequestMapping("/hello")
    public String index() {
    	ServletRequestAttributes servletRequestAttributes = (ServletRequestAttributes)RequestContextHolder.getRequestAttributes();
        HttpServletRequest request = servletRequestAttributes.getRequest();
        // 从http请求得到客户端证书
        String certStr = request.getHeader("ssl_cert");
        // 打印客户端证书
        System.out.println(certStr);
        // 验证客户端证书与账户一致性 这里假设用户输入的是 "zhoufeng@iqianjin.com"
        if(!StringUtils.isEmpty(certStr) && checkLogin("zhoufeng@iqianjin.com", certStr)){
			return "用户名与证书不匹配！";
		}
        return "Hello World";
    }
    
    /**
     * Description: 登陆证书校验
     * @Version1.0 2019年5月15日 上午10:21:51 by 周峰（zhoufeng@iqianjin.com）创建
     * @param userName
     * @param certStr
     * @return
     */
    private boolean checkLogin(String userName, String certStr){
    	boolean flag = false;
    	// 从证书得到用户id
    	String userId = BASE64Decode.decodeCert(certStr);
    	// 根据用户id 查询数据库得到 用户名 这里假设得到的是 zhoufeng@iqanjin.com
		String userNameByUserId = "zhoufeng@iqanjin.com";
		if(!userName.equals(userNameByUserId)){
			flag = true;
		}
    	return flag;
    }
}
