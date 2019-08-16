package com.alias.tokendemo.util;

import org.apache.commons.codec.digest.DigestUtils;

/**
 * @ClassName PsswordDigestUtils
 * @Description: 密码加密工具类
 * @Author ChenShengLi
 * @Date 2019/8/16
 **/
public class PasswordDigestUtils {

    public static String encryptPassword(String password) {
        return DigestUtils.sha1Hex(password + "wslg");
    }

    /**
     * 使用sha1Hex单向加密算法进行加密
     *
     * @param password
     * @param salt
     * @return
     */
    public static String encryptPassword(String password, String salt) {
        return DigestUtils.sha1Hex(password + salt);
    }
}
