package com.alias.tokendemo.exception;

/**
 * @ClassName JWTUtil
 * @Description: TODO
 * @Author ChenShengLi
 * @Date 2019/8/16
 **/
public class JwtIllegalArgumentException extends Exception {
    public JwtIllegalArgumentException(String s) {
        super(s);
    }

    public JwtIllegalArgumentException(String msg, Throwable cause) {
        super(msg, cause);
    }
}
