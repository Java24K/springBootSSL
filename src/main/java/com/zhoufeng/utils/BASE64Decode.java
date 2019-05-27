package com.zhoufeng.utils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Description: 证书解析类
 * All Rights Reserved.
 * @version 1.0  2019年5月15日 上午10:24:21  by 周峰（zhoufeng@iqianjin.com）创建
 */
public class BASE64Decode {
	
	private BASE64Decode(){}
	
	private static final Logger LOGGER = LoggerFactory.getLogger(BASE64Decode.class);

	private static byte[] base64DecodeChars = new byte[] { -1, -1, -1, -1, -1,
			-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
			-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
			-1, -1, -1, -1, 62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58, 59,
			60, 61, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
			10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1,
			-1, -1, -1, -1, -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37,
			38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1,
			-1, -1 };

	
	/**
	 * Description: 解码证书内容 把字符变成字节数组
	 * @Version1.0 2019年5月15日 上午10:26:55 by 周峰（zhoufeng@iqianjin.com）创建
	 * @param str
	 * @return
	 */
	public static byte[] decode(String str) {
		byte[] data = str.getBytes();
		int len = data.length;
		ByteArrayOutputStream buf = new ByteArrayOutputStream(len);
		int i = 0;
		int b1, b2, b3, b4;
		while (i < len) { /* b1 */
			do {
				b1 = base64DecodeChars[data[i++]];
			} while (i < len && b1 == -1);
			if (b1 == -1) {
				break;
			} /* b2 */
			do {
				b2 = base64DecodeChars[data[i++]];
			} while (i < len && b2 == -1);
			if (b2 == -1) {
				break;
			}
			buf.write((int) ((b1 << 2) | ((b2 & 0x30) >>> 4))); /* b3 */
			do {
				b3 = data[i++];
				if (b3 == 61) {
					return buf.toByteArray();
				}
				b3 = base64DecodeChars[b3];
			} while (i < len && b3 == -1);
			if (b3 == -1) {
				break;
			}
			buf.write((int) (((b2 & 0x0f) << 4) | ((b3 & 0x3c) >>> 2))); /* b4 */
			do {
				b4 = data[i++];
				if (b4 == 61) {
					return buf.toByteArray();
				}
				b4 = base64DecodeChars[b4];
			} while (i < len && b4 == -1);
			if (b4 == -1) {
				break;
			}
			buf.write((int) (((b3 & 0x03) << 6) | b4));
		}
		return buf.toByteArray();
	}

	
	/**
	 * Description: 解析证书信息,获取用户id
	 * @Version1.0 2019年5月15日 上午10:25:19 by 周峰（zhoufeng@iqianjin.com）创建
	 * @param certStr
	 * @return
	 */
	public static String decodeCert(String certStr){
		try {
			String replaceCertStr = certStr.replaceAll("-----BEGIN CERTIFICATE-----", "")
					.replaceAll("-----END CERTIFICATE-----", "");
			byte[] decoded = decode(replaceCertStr);
			X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509")
					.generateCertificate(new ByteArrayInputStream(decoded));
			
			// SubjectDN串 “CN=1127, OU=dc, O=dc, L=bj, ST=bj, C=cn”
			// 从SubjectDN串中得到CN的参数 例如这里的1127
			String userId = cert.getSubjectDN().getName().split(",")[0].split("=")[1];
			System.out.println("证书中的用户id为：" + userId);
			// 验证客户端证书是否过期
			if (verifyCertificate(cert)) {
				return userId;
			} else {
				return "";
			}
		} catch (CertificateException e) {
			LOGGER.info("数据输出失败", e);
			return "";
		}
	}

	/**
	 * Description: 校验证书是否过期
	 * @Version1.0 2019年5月15日 上午10:25:00 by 周峰（zhoufeng@iqianjin.com）创建
	 * @param certificate
	 * @return
	 */
	private static boolean verifyCertificate(X509Certificate certificate) {
		boolean valid = true;
		try {
			certificate.checkValidity();
		} catch (Exception e) {
			LOGGER.info("数据输出失败", e);
			valid = false;
		}
		return valid;
	}

}
