package com.alias.tokendemo.util;


import com.alias.tokendemo.exception.JwtIllegalArgumentException;
import io.jsonwebtoken.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;
import sun.misc.BASE64Decoder;

import java.security.Key;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;
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
        这里将生成的公钥与私钥取出来放在配置文件中，通过读取配置文件的形式获取，也可将生成的密钥保存在服务器中，添加一个RSA工具类读取文件并获取私钥与公钥来实现
 * @Author ChenShengLi
 * @Date 2019/8/16
 **/
@Slf4j
public class JWTUtil {
    public static String CLIENT_ID;
    public static String AUDIENCE;
    public static long MINUTES;
    private static Key privateKey;
    public static Key publicKey;

    public JWTUtil() {

    }

    static{
        try{
            Map<String,Object> param = ResourceUtils.getResource("token").getMap();
            CLIENT_ID = (String) param.get("token.clientId");
            AUDIENCE = (String) param.get("token.audience");
            MINUTES = param.get("token.minutes") == null ? 1440L :(long)Integer.parseInt((String)param.get("token.minutes"));
            byte[] keyBytes = (new BASE64Decoder()).decodeBuffer((String)param.get("token.publicKey"));
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            publicKey = keyFactory.generatePublic(publicKeySpec);
            byte[] privateKeyBytes = (new BASE64Decoder()).decodeBuffer((String)param.get("token.privateKey"));
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            KeyFactory privateKeyFactory = KeyFactory.getInstance("RSA");
            privateKey = privateKeyFactory.generatePrivate(privateKeySpec);
            System.out.println("2222");
        } catch (Exception var6) {
            log.error("无法加载配置文件 token.properties，请确认文件是否存在！");
        }
    }

    private static void checkParams() {
        if(StringUtils.isEmpty(CLIENT_ID)) {
            throw new RuntimeException("请检查token.clientId参数是否存在！");
        }else if(StringUtils.isEmpty(AUDIENCE)) {
            throw new RuntimeException("请检查token.audience参数是否存在！");
        }else if(privateKey == null) {
            throw new RuntimeException("请检查token.privateKey参数是否存在！");
        }else if(publicKey == null) {
            throw new RuntimeException("请检查token.publicKey参数是否存在！");
        }
    }

    public static String createToken(Map<String,Object> payLoadMap) throws JwtIllegalArgumentException {
        checkParams();
        return createToken(CLIENT_ID,AUDIENCE,MINUTES,payLoadMap);
    }

    public static String createToken(long minutes,Map<String,Object> payLoadMap) throws JwtIllegalArgumentException {
        checkParams();
        return createToken(CLIENT_ID,AUDIENCE,minutes,payLoadMap);
    }

    public static String createToken(String issUser,String audience,long minutes,Map<String,Object> payLoadMap) throws JwtIllegalArgumentException {
        if(StringUtils.isEmpty(issUser)) {
            log.info("令牌创建者为空");
            return null;
        }else if(StringUtils.isEmpty(audience)) {
            log.info("令牌使用者为为空");
            return null;
        }else if(minutes <= 0L) {
            log.info("令牌有效时间为空");
            return null;
        }
        long nowMillis = System.currentTimeMillis();
        Date now = new Date();
        long expMills = nowMillis + minutes * 60L * 1000L;
        Date exp = new Date(expMills);
        String token = "";
        try{
            token = Jwts.builder()
                    .setClaims(payLoadMap)
                    .setIssuedAt(now)
                    .setSubject(issUser)
                    .setAudience(issUser)
                    .setIssuer(issUser)
                    .signWith(SignatureAlgorithm.RS256, privateKey)
                    .setExpiration(exp).compact();
        }catch (ClaimJwtException var) {
            Claims claims = var.getClaims();
            Map<String,Object> payLoad = new HashMap<>();
            payLoad.putAll(claims);
            throw new JwtIllegalArgumentException("获取令牌token错误！" + var.getMessage());
        } catch (JwtException var15) {
            throw new JwtIllegalArgumentException("获取 token 令牌错误！" + var15.getMessage());
        }
        if(StringUtils.isEmpty(token)) {
            throw new JwtIllegalArgumentException("获取 token 令牌错误！令牌为空");
        }else{
            return token;
        }
    }

    public static Map<String,Object> checkToken(String token) throws JwtIllegalArgumentException {
        checkParams();
        return checkToken(token,CLIENT_ID,AUDIENCE);
    }

    public static Map<String,Object> checkToken(String token,String isUser,String audience) throws JwtIllegalArgumentException {
        Map payLoadMap = null;
        try{
            payLoadMap = (Map)Jwts.parser()
                    .setSigningKey(publicKey)
                    .requireIssuer(isUser)
                    .requireAudience(audience)
                    .parseClaimsJws(token)
                    .getBody();
        }catch(ClaimJwtException var6) {
            Claims claims = var6.getClaims();
            HashMap payLoad = new HashMap();
            payLoad.putAll(claims);
            throw new JwtIllegalArgumentException("校验token失败！"+var6.getMessage());
        }catch (JwtException var7) {
            throw new JwtIllegalArgumentException("校验token失败！"+var7.getMessage());
        }
        if (payLoadMap == null) {
            throw new JwtIllegalArgumentException("校验 token 失败！");
        } else {
            return payLoadMap;
        }
    }

    /**
     * 获取公钥
     * @param keyBytes
     * @return
     * @throws Exception
     */
    public static void getPublicKey(byte[] keyBytes) throws Exception {
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        publicKey = keyFactory.generatePublic(publicKeySpec);
    }

    /**
     * 获取密钥
     * @param keyBytes
     * @return
     * @throws Exception
     */
    public static void getPrivateKey(byte[] keyBytes) throws Exception {
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory privateKeyFactory = KeyFactory.getInstance("RSA");
        privateKey = privateKeyFactory.generatePrivate(privateKeySpec);
    }



    public static void main(String[] args) throws JwtIllegalArgumentException {
        Map<String, Object> map = new HashMap<>();
        map.put("userId", 222);
        map.put("userRole", "member");
        String token = JWTUtil.createToken(map);
        System.out.println(token);
        Map<String, Object> stringObjectMap = JWTUtil.checkToken(token);
        System.out.println(stringObjectMap);
    }
}
