package com.alias.tokendemo.util;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.joda.time.DateTime;

import java.util.HashMap;
import java.util.Map;

/**
 * @ClassName JWTUtil
 * @Description:
 *      token生成工具类，主要使用的是RSA256单向加密算法，比起HS256双向加密算法更加安全，
 *      这里通过ssh-keygen的方式生成token签名所需的公钥、密钥，生成方法：
        生成加密长度4096位密钥 
        生成私钥：ssh-keygen -t rsa -b 4096 -f ${private}.key
        生成公钥：openssl rsa -in ${private}.key -pubout -outform PEM -out ${public}.key.pub
        转换格式：openssl pkcs8 -topk8 -inform PEM -in jwtRS256.key -outform pem -nocrypt -out pkcs8.pem
        生成加密长度1024位密钥
        生成私钥：ssh-keygen -t rsa -b 1024 -f ${private}.key
        生成公钥：openssl rsa -in ${private}.key -pubout -outform PEM -out ${public}.key.pub
        转换格式：openssl pkcs8 -topk8 -inform PEM -in jwtRS256.key -outform pem -nocrypt -out pkcs8.pem
 * @Author ChenShengLi
 * @Date 2019/8/16
 **/
public class JWTHelper {
    private static RsaKeyHelper rsaKeyHelper = new RsaKeyHelper();

    private static final String ISSUE_USER = "wslg";
    /**
     * 公钥文件
     */
    private static final String PUBLIC_KEY_FILE = "token";
    /**
     * 密钥文件
     */
    private static final String PRIVATE_KEY_FILE = "token";

    private static final String PRIVATE_KEY = "token.privateKey";

    private static final String PUBLIC_KEY = "token.publicKey";

    /**
     * 密钥加密token
     * @param payLoadMap
     * @return
     * @throws Exception
     */
    public static String generateToken(Map<String, Object> payLoadMap) throws Exception {

        return generateToken(payLoadMap, PRIVATE_KEY_FILE, PRIVATE_KEY,10000000);
    }

    /**
     * 密钥加密token
     * @param payLoadMap
     * @param expire
     * @return
     * @throws Exception
     */
    public static String generateToken(Map<String, Object> payLoadMap, int expire) throws Exception {
        return generateToken(payLoadMap, PRIVATE_KEY_FILE, PRIVATE_KEY,expire);
    }

    /**
     * 密钥加密token
     *
     * @param payLoadMap
     * @param priKeyPath
     * @param expire
     * @return
     * @throws Exception
     */
    public static String generateToken(Map<String, Object> payLoadMap, String priKeyPath, String keyName, int expire) throws Exception {
        String compactJws = Jwts.builder()
                .setSubject(ISSUE_USER)
                .setClaims(payLoadMap)
                .signWith(SignatureAlgorithm.RS256, rsaKeyHelper.getPrivateKey(priKeyPath, keyName))
                .compact();
        return compactJws;
    }

    /**
     * 密钥加密token
     *
     * @param payLoadMap
     * @param priKey
     * @param expire
     * @return
     * @throws Exception
     */
    public static String generateToken(Map<String, Object> payLoadMap, byte priKey[], int expire) throws Exception {
        String compactJws = Jwts.builder()
                .setSubject(ISSUE_USER)
                .setClaims(payLoadMap)
                .setExpiration(DateTime.now().plusSeconds(expire).toDate())
                .signWith(SignatureAlgorithm.RS256, rsaKeyHelper.getPrivateKey(priKey))
                .compact();
        return compactJws;
    }

    /**
     * 公钥解析token
     *
     * @param token
     * @return
     * @throws Exception
     */
    public static Map<String, Object> parserToken(String token) throws Exception {
        Map<String, Object> payLoadMap = Jwts.parser()
                .setSigningKey(rsaKeyHelper.getPublicKey(PUBLIC_KEY_FILE, PUBLIC_KEY))
                .parseClaimsJws(token)
                .getBody();
        return payLoadMap;
    }

    /**
     * 公钥解析token
     *
     * @param token
     * @return
     * @throws Exception
     */
    public static Map<String, Object> parserToken(String token, String pubKeyPath, String publicKey) throws Exception {
        Map<String, Object> payLoadMap = Jwts.parser()
                .setSigningKey(rsaKeyHelper.getPublicKey(pubKeyPath, publicKey))
                .parseClaimsJws(token)
                .getBody();
        return payLoadMap;
    }
    /**
     * 公钥解析token
     *
     * @param token
     * @return
     * @throws Exception
     */
    public static Map<String, Object> parserToken(String token, byte[] pubKey) throws Exception {
        Map<String, Object> payLoadMap = Jwts.parser()
                .setSigningKey(rsaKeyHelper.getPublicKey(pubKey))
                .parseClaimsJws(token)
                .getBody();
        return payLoadMap;
    }
    /**
     * 获取token中的用户信息
     *
     * @param token
     * @param pubKeyPath
     * @return
     * @throws Exception
     */
    public static  Map<String, Object> getInfoFromToken(String token, String pubKeyPath, String key) throws Exception {
        Map<String, Object> claimsJws = parserToken(token, pubKeyPath, key);
        return claimsJws;
    }

    /**
     * 获取token中的用户信息
     *
     * @param token
     * @param pubKey
     * @return
     * @throws Exception
     */
    public static Map<String, Object> getInfoFromToken(String token, byte[] pubKey) throws Exception {
        Map<String, Object> claimsJws = parserToken(token, pubKey);
        return claimsJws;
    }

    public static void main(String[] args) throws Exception {
        Map<String, Object> map = new HashMap<>();
        map.put("userId", 222);
        map.put("userRole", "member");
        String generateToken = JWTHelper.generateToken(map);
        System.out.println(generateToken);
        Map<String, Object> stringObjectMap = JWTHelper.parserToken(generateToken);
        System.out.println(stringObjectMap);
    }

}
